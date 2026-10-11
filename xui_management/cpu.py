import time


def _proc_stat():
    with open("/proc/stat", "r", encoding="ascii") as handle:
        parts = handle.readline().split()
    if not parts or parts[0] != "cpu":
        raise OSError("unexpected /proc/stat")
    nums = [int(x) for x in parts[1:]]
    idle = nums[3] + (nums[4] if len(nums) > 4 else 0)
    return idle, sum(nums)


def cpu_percent(sample=0.4):
    """Return host CPU percent, or None when it cannot be read.

    The sample is taken from /proc/stat so the VPS does not need extra packages.
    """
    try:
        idle0, total0 = _proc_stat()
        time.sleep(sample)
        idle1, total1 = _proc_stat()
    except OSError:
        return None
    delta = total1 - total0
    if delta <= 0:
        return None
    used = 100.0 * (1.0 - ((idle1 - idle0) / float(delta)))
    if used < 0:
        return 0.0
    if used > 100:
        return 100.0
    return used
