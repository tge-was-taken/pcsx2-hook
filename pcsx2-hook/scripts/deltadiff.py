#!/usr/bin/env python3
"""Did a render change help on the pixels it actually touched?

Usage: scripts/deltadiff.py <reference.png> <before.ppm> <after.ppm>
"""
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from refdiff import read_any, read_ppm  # noqa: E402


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        return 2
    rw, rh, ref = read_any(sys.argv[1])
    _, _, before = read_ppm(sys.argv[2])
    _, _, after = read_ppm(sys.argv[3])
    touched = beforeErr = afterErr = 0
    beforeSigned = afterSigned = 0
    for i in range(0, rw * rh * 3, 3):
        if before[i : i + 3] == after[i : i + 3]:
            continue
        touched += 1
        for c in range(3):
            beforeErr += abs(before[i + c] - ref[i + c])
            afterErr += abs(after[i + c] - ref[i + c])
            beforeSigned += before[i + c] - ref[i + c]
            afterSigned += after[i + c] - ref[i + c]
    if not touched:
        print("no pixels changed")
        return 0
    n = touched * 3
    print(f"touched {touched} px ({touched * 100.0 / (rw * rh):.2f}% of frame)")
    print(f"  before  mean abs {beforeErr / n:6.3f}  signed {beforeSigned / n:+7.3f}")
    print(f"  after   mean abs {afterErr / n:6.3f}  signed {afterSigned / n:+7.3f}")
    verdict = "closer" if afterErr < beforeErr else "further" if afterErr > beforeErr else "unchanged"
    print(f"  -> {verdict} to the reference by {abs(beforeErr - afterErr) / n:.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
