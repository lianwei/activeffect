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

How to use:

1. Apply the cpufreq_activeffect.c to drivers/cpufreq folder
2. Apply the patch of 0001-cpufreq-activeffect-enable-activeffect-governor-to-b
3. Enable activeffect governor in defconfig file:
        CONFIG_CPU_FREQ_GOV_ACTIVEFFECT=y
4. Switch to activeffect governor in startup script
