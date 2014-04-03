Activeffect Governor (Active Effect)
===================================

The activeffect is brand new cpufreq governor.

Unlike the other governor, the CPUFreq scale up or scale down in two
place. A active timer is set when CPU is active to increase the CPU
frequency ASAP. It will only try to decrease the CPUfrequency when CPU
go to idle mode.

This governor is still based on the CPU load, but the history data is
also considered when calculating the current CPU load.

Besides the general cpufreq governor feature, it has the below advanced
features:

1. Frequency control:
Always increase frequency when cpu is active. So it will never down cpu
frequency when cpu is active. And it will try to scale down the cpufreq
when cpu go to idle mode.

2. Predicted:
It will predict the sleep length scale down the cpufreq according to the
predicted sleep time.

3. Active Boost:
With the Active Boost, it will boost the cpufreq to the boost frequency
if the cpu continuous running in active mode for a specified period.

The tunable values for this governor are:

timer_rate: The sample rate for active timer to re-evaluate cpu load
when the system is not idle.
Default is 20 mS.

target_load: Specify the target CPU load that we want to adjust to.
Default is 70.

down_load: Scale down the frequency if load is less than down_load.
Default is 60.

min_down_duration: The minimum amount of time that can be used to
decrease the CPU frequency.
Default is 20 mS

io_is_busy: this parameter takes a value of '0' or '1'. When set to '1',
the iowait time will be calculated as busy time.
Default is 0.

descend_rate: Specify the descend rate which will remove the old idle
time.
Default is 1.

boost: If non-zero, immediately boost speed of all CPUs to at least
boost freq for specified x mS until zero is written to this attribute or
timeout. If zero, disable boost and allow CPU speeds to drop below boost
freq according to load as usual.

active_boost: Boost the CPU frequency to at least boost_freq during a
continuous active timer callback. The value specify at which timer cycle
to boost it. '0' is the default value to disable active_boost.
Default is 0.

boost_freq: The minimum frequency that can meet the target performance.
This is the important parameter and must be set to achieve the best
battery life. when CPU freq is greater or equal to boost_freq, then the
CPU work in boost mode.
Default is the MAX frequency.

boost_timer_rate: The sample rate that CPU work in boost mode.
Default is 100 mS.

boost_target_load: the target load that CPU work in boost mode.
Default is 90.
