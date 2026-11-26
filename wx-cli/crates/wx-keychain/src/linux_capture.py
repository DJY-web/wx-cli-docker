"""ARM64 Linux WCDB capture helper. Never restarts/logs out WeChat automatically.

ELF64 ADRP references + GOT + .eh_frame_hdr identify the setCipherKey entry.
GDB reads only its 32-byte UnsafeData argument and validates it against a known
database first page before saving a private intermediate file. No raw key logs.
"""
import argparse
import array
import bisect
import hashlib
import os
from pathlib import Path
import selectors
import signal
import struct
import subprocess
import sys
import time

ANCHOR = b"com.Tencent.WCDB.Config.Cipher"


def adrp_target(ins, pc):
    if ins & 0x9F000000 != 0x90000000:
        return None
    delta = ((ins >> 5 & 0x7FFFF) << 2) | (ins >> 29 & 3)
    if delta & 0x100000:
        delta -= 0x200000
    return (pc & ~4095) + (delta << 12), ins & 31


def address_use(first, second, pc, mode):
    decoded = adrp_target(first, pc)
    if decoded is None:
        return None
    page, register = decoded
    if second >> 5 & 31 != register:
        return None
    if mode == "add" and second & 0xFF000000 == 0x91000000:
        return page + ((second >> 10 & 4095) << (12 if second >> 22 & 1 else 0)), second & 31
    if mode == "load" and second & 0xFFC00000 == 0xF9400000:
        return page + (second >> 10 & 4095) * 8, second & 31
    return None


def locate(binary):
    blob = Path(binary).read_bytes()
    if blob[:6] != b"\x7fELF\x02\x01":
        raise ValueError("capture requires an ELF64 little-endian executable")
    h = struct.unpack_from("<HHIQQQIHHHHHH", blob, 16)
    if h[1] != 183:
        raise ValueError("debugger capture currently supports Linux ARM64 only; use key scan/key set on other architectures")
    rows = [struct.unpack_from("<IIQQQQIIQQ", blob, h[5] + i * h[10]) for i in range(h[11])]
    names = blob[rows[h[12]][4]:rows[h[12]][4] + rows[h[12]][5]]
    sections = {names[r[0]:].split(b"\0", 1)[0].decode(): r for r in rows}
    text, rodata, unwind = (sections[n] for n in (".text", ".rodata", ".eh_frame_hdr"))
    ro = blob[rodata[4]:rodata[4] + rodata[5]]
    anchors = set()
    offset = 0
    while (offset := ro.find(ANCHOR, offset)) >= 0:
        anchors.add(rodata[3] + offset)
        offset += len(ANCHOR)
    instructions = array.array("I", blob[text[4]:text[4] + text[5] - text[5] % 4])
    if sys.byteorder != "little":
        instructions.byteswap()

    def references(targets, mode):
        result = []
        for i, ins in enumerate(instructions):
            if ins & 0x9F000000 != 0x90000000:
                continue
            for distance in range(1, min(5, len(instructions) - i)):
                use = address_use(ins, instructions[i + distance], text[3] + i * 4, mode)
                if use and use[0] in targets:
                    result.append((i, distance, use[1]))
        return result

    got_slots = set()
    for i, distance, register in references(anchors, "add"):
        if register != 0:
            continue
        # AArch64 indirect aggregate return address is x8. Global StringView
        # initialization loads that address via GOT next to the literal.
        for j in range(max(0, i - 4), i + 1):
            for k in range(i + distance + 1, min(i + distance + 4, len(instructions))):
                use = address_use(instructions[j], instructions[k], text[3] + j * 4, "load")
                if use and use[1] == 8:
                    got_slots.add(use[0])
    offset = unwind[4]
    if blob[offset:offset + 4] != bytes.fromhex("011b033b"):
        raise ValueError("unrecognized unwind encoding; refusing to guess a breakpoint")
    count = struct.unpack_from("<I", blob, offset + 8)[0]
    starts = [unwind[3] + struct.unpack_from("<i", blob, offset + 12 + i * 8)[0] for i in range(count)]
    candidates = set()
    for i, _, register in references(got_slots, "load"):
        if register != 1:
            continue
        pc = text[3] + i * 4
        index = bisect.bisect_right(starts, pc) - 1
        if index >= 0 and pc - starts[index] < 2048:
            start = starts[index]
            code = blob[text[4] + start - text[3]:text[4] + i * 4]
            if struct.pack("<I", 0xAA0103E0) in code:  # mov x0,x1: UnsafeData::size()
                candidates.add(start)
    if len(candidates) != 1:
        raise ValueError(f"expected exactly one validated setCipherKey candidate, found {len(candidates)}")
    return candidates.pop(), h[0], hashlib.sha256(blob).hexdigest()


def runtime_bias(pid, elf_type):
    if elf_type == 2:
        return 0
    executable = os.readlink(f"/proc/{pid}/exe")
    bases = []
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) == 6 and fields[5] == executable:
            bases.append(int(fields[0].split("-")[0], 16) - int(fields[2], 16))
    if not bases:
        raise ValueError("cannot determine the executable load bias")
    return min(bases)


GDB_CODE = r'''
import gdb, hashlib, hmac, struct, os
pages = []
for path in DB_FILES:
    try:
        with open(path, 'rb') as f:
            page = f.read(4096)
        if len(page) == 4096:
            pages.append(page)
    except OSError:
        pass
class KeyBreakpoint(gdb.Breakpoint):
    def stop(self):
        try:
            arg = int(gdb.parse_and_eval('$x1'))
            obj = gdb.selected_inferior().read_memory(arg, 24).tobytes()
            pointer, size = struct.unpack_from('<QQ', obj, 8)
            if size != 32 or not pointer:
                return False
            key = gdb.selected_inferior().read_memory(pointer, size).tobytes()
            for page in pages:
                salt = page[:16]
                enc = hashlib.pbkdf2_hmac('sha512', key, salt, 256000, 32)
                macsalt = bytes(b ^ 0x3a for b in salt)
                mac = hashlib.pbkdf2_hmac('sha512', enc, macsalt, 2, 32)
                digest = hmac.new(mac, page[16:4032] + struct.pack('<I', 1), 'sha512').digest()
                if hmac.compare_digest(digest, page[4032:4096]):
                    fd = os.open(OUTPUT, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
                    with os.fdopen(fd, 'w') as f:
                        f.write(key.hex())
                    print('WX_CLI_CAPTURE_VALIDATED', flush=True)
                    return True
        except (gdb.error, OSError, ValueError, struct.error):
            pass
        return False
bp = KeyBreakpoint('*' + hex(HOOK), internal=True)
print('WX_CLI_CAPTURE_READY', flush=True)
try:
    gdb.execute('continue')
except (KeyboardInterrupt, gdb.error):
    pass
finally:
    try:
        bp.delete()
        gdb.execute('detach')
    except gdb.error:
        pass
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--output", required=True)
    parser.add_argument("--db", action="append", required=True)
    parser.add_argument("--locate-only", action="store_true")
    args = parser.parse_args()
    comm = Path(f"/proc/{args.pid}/comm").read_text().strip()
    if comm not in {"wechat", "WeChat", "weixin"}:
        raise ValueError("target PID is not the main WeChat process")
    hook, elf_type, fingerprint = locate(f"/proc/{args.pid}/exe")
    if args.locate_only:
        print(f"ARM64 setCipherKey offset: 0x{hook:x}; executable SHA256: {fingerprint}")
        return
    status = Path(f"/proc/{args.pid}/status").read_text()
    if any(line.startswith("TracerPid:") and line.split()[1] != "0" for line in status.splitlines()):
        raise ValueError("WeChat already has a debugger attached; refusing to interfere")
    output = Path(args.output)
    if output.exists():
        raise ValueError("capture output must be a new private file")
    script = output.with_suffix(".gdb")
    setup = f"DB_FILES = {args.db!r}\nOUTPUT = {str(output)!r}\nHOOK = {runtime_bias(args.pid, elf_type) + hook}\n"
    command = "set pagination off\nset confirm off\nset print thread-events off\nset debuginfod enabled off\nattach " + str(args.pid) + "\npython\n" + setup + GDB_CODE + "\nend\nquit\n"
    fd = os.open(script, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(command)
    process = subprocess.Popen(["gdb", "-q", "--nx", "--batch", "-x", str(script)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + args.timeout
    interrupted = False
    try:
        while process.poll() is None:
            if time.monotonic() >= deadline and not interrupted:
                os.killpg(process.pid, signal.SIGINT)
                interrupted = True
                deadline = time.monotonic() + 8
            elif time.monotonic() >= deadline:
                process.terminate()
                break
            for item, _ in selector.select(0.2):
                line = item.fileobj.readline()
                if b"WX_CLI_CAPTURE_READY" in line:
                    print("Debugger ready. Manually sign out and sign in to the container WeChat to trigger capture.", file=sys.stderr, flush=True)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGINT)
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        selector.close()
        process.stdout.close()
        script.unlink(missing_ok=True)
    if not output.exists():
        raise ValueError("no validated key captured; WeChat was not restarted automatically")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("Linux capture: " + str(error), file=sys.stderr)
        sys.exit(1)
