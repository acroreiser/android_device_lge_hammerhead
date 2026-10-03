#!/system/vendor/bin/sh
#
# Script to setup many things after boot

echo 3000000 > /proc/sys/kernel/sched_min_granularity_ns

echo 1 > /proc/sys/kernel/sched_bore
echo 1 > /proc/sys/kernel/sched_burst_fork_atavistic
echo 19 > /proc/sys/kernel/sched_burst_penalty_offset
echo 2048 > /proc/sys/kernel/sched_burst_penalty_scale

echo 100 > /dev/blkio/background/blkio.weight

echo $(pidof system_server) > /dev/cpuctl/top-app/tasks
echo 5120 > /dev/cpuctl/foreground/cpu.shares

echo NO_TTWU_QUEUE > /d/sched_features
echo NO_RT_RUNTIME_SHARE > /d/sched_features
echo NO_GENTLE_FAIR_SLEEPERS > /d/sched_features
echo NO_START_DEBIT > /d/sched_features

echo 4 > /proc/sys/vm/kswapd_threads

echo 1 > /proc/sys/vm/watermark_scale_factor

# Tune lmk minfree and timeout
echo "27648,32256,36864,46080,51200,61440" > /sys/module/lowmemorykiller/parameters/minfree
echo 150 > /sys/module/lowmemorykiller/parameters/kill_timeout_ms

# Some apps may crash due to SIGBUS on misaligned access
echo 2 > /proc/cpu/alignment

/vendor/bin/timekeep restore
