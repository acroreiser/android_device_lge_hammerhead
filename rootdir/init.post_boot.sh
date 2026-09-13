#!/system/vendor/bin/sh
#
# Script to setup many things after boot

echo 3000000 > /proc/sys/kernel/sched_min_granularity_ns

echo 1 > /proc/sys/kernel/sched_bore
echo 1 > /proc/sys/kernel/sched_burst_fork_atavistic
echo 19 > /proc/sys/kernel/sched_burst_penalty_offset
echo 2048 > /proc/sys/kernel/sched_burst_penalty_scale

echo 100 > /dev/blkio/background/blkio.weight

echo 4 > /proc/sys/vm/kswapd_threads

echo 1 > /proc/sys/vm/watermark_scale_factor

# Tune lmk minfree and timeout
echo "27648,32256,36864,46080,51200,61440" > /sys/module/lowmemorykiller/parameters/minfree
echo 150 > /sys/module/lowmemorykiller/parameters/kill_timeout_ms

/vendor/bin/timekeep restore
