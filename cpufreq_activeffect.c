/*
 *  linux/drivers/cpufreq/cpufreq_activeffect.c
 *
 *  Copyright (C) 2013 Lianwei Wang <lian-wei.wang@motorola.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Derived from interactive & ondemand governor
 */
#include <linux/cpu.h>
#include <linux/kernel.h>
#include <linux/kernel_stat.h>
#include <linux/module.h>
#include <linux/cpufreq.h>
#include <linux/init.h>
#include <linux/tick.h>
#include <linux/kthread.h>
#include <asm/cputime.h>

#define TRANSITION_LATENCY_LIMIT		(10 * 1000 * 1000)

static int cpufreq_governor_activeffect(struct cpufreq_policy *policy,
				unsigned int event);

#ifndef CONFIG_CPU_FREQ_DEFAULT_GOV_ACTIVEFFECT
static
#endif
struct cpufreq_governor cpufreq_gov_activeffect = {
	.name		= "activeffect",
	.governor	= cpufreq_governor_activeffect,
	.max_transition_latency = TRANSITION_LATENCY_LIMIT,
	.owner		= THIS_MODULE,
};

struct cpufreq_activeffect_cpuinfo {
	unsigned int target_freq;
	unsigned int scaling_freq;
	unsigned int max_freq;
	int governor_enabled;
	int timer_accu_count;
	cputime64_t prev_cpu_idle, cpu_idle;
	cputime64_t prev_cpu_iowait, cpu_iowait;
	cputime64_t prev_cpu_wall, cpu_wall;
	cputime64_t accu_cpu_wall;
	cputime64_t prev_cpu_nice, cpu_nice;
	struct timer_list cpu_timer;
	struct cpufreq_policy *policy;
	struct cpufreq_frequency_table *freq_table;
	struct rw_semaphore enable_sem;
};

static DEFINE_PER_CPU(struct cpufreq_activeffect_cpuinfo, cpuinfo);

/* realtime thread handles frequency scaling */
static struct task_struct *scaling_task;
static cpumask_t scaling_cpumask;
static spinlock_t scaling_cpumask_lock;

static unsigned int gov_enable;	/* number of CPUs using this policy */
/*
 * gov_mutex protects gov_enable in governor start/stop.
 */
static DEFINE_MUTEX(gov_mutex);

/*
 * The sample rate of the timer used to increase frequency
 */
#define DEFAULT_TIMER_RATE (20 * USEC_PER_MSEC)
static unsigned long timer_rate = DEFAULT_TIMER_RATE;
/* The sample rate above bootst frequency */
#define DEFAULT_BOOST_TIMER_RATE (100 * USEC_PER_MSEC)
static unsigned long boost_timer_rate = DEFAULT_BOOST_TIMER_RATE;

#define DEFAULT_TARGET_LOAD 70
static unsigned int target_load = DEFAULT_TARGET_LOAD;
#define DEFAULT_BOOST_TARGET_LOAD 90
static unsigned int boost_target_load = DEFAULT_BOOST_TARGET_LOAD;

static unsigned int boost_freq; /* in kHz */

static unsigned int boost; /* in millisecond */
static ktime_t boost_ktime;

static unsigned int active_boost; /* boost  the cpufreq in active mode*/

static unsigned long min_down_duration = DEFAULT_TIMER_RATE; /* in us */

#define DEFAULT_DOWN_LOAD 60
static unsigned int down_load = DEFAULT_DOWN_LOAD;

#define DEFAULT_DESCEND_RATE 1
static unsigned int descend_rate = DEFAULT_DESCEND_RATE;

static int io_is_busy;

static inline cputime64_t get_cpu_idle_time_jiffy(unsigned int cpu,
						  cputime64_t *wall)
{
	u64 idle_time;
	u64 cur_wall_time;
	u64 busy_time;

	cur_wall_time = jiffies64_to_cputime64(get_jiffies_64());

	busy_time  = kcpustat_cpu(cpu).cpustat[CPUTIME_USER];
	busy_time += kcpustat_cpu(cpu).cpustat[CPUTIME_SYSTEM];
	busy_time += kcpustat_cpu(cpu).cpustat[CPUTIME_IRQ];
	busy_time += kcpustat_cpu(cpu).cpustat[CPUTIME_SOFTIRQ];
	busy_time += kcpustat_cpu(cpu).cpustat[CPUTIME_STEAL];
	busy_time += kcpustat_cpu(cpu).cpustat[CPUTIME_NICE];

	idle_time = cur_wall_time - busy_time;
	if (wall)
		*wall = jiffies_to_usecs(cur_wall_time);

	return jiffies_to_usecs(idle_time);
}

static inline cputime64_t get_cpu_idle_time(unsigned int cpu,
					    cputime64_t *wall)
{
	u64 idle_time = get_cpu_idle_time_us(cpu, wall);

	if (idle_time == -1ULL)
		idle_time = get_cpu_idle_time_jiffy(cpu, wall);
	else if (!io_is_busy)
		idle_time += get_cpu_iowait_time_us(cpu, wall);

	return idle_time;
}

static void scaling_freq_update(struct cpufreq_activeffect_cpuinfo *pcpu)
{
	unsigned int max_freq;
	unsigned int j;
	unsigned long flags;
	struct cpufreq_activeffect_cpuinfo *scpu;

	if (!pcpu || !pcpu->policy)
		return;

	scpu = &per_cpu(cpuinfo, pcpu->policy->cpu);

	max_freq = 0;
	for_each_cpu(j, pcpu->policy->cpus) {
		struct cpufreq_activeffect_cpuinfo *jcpu =
					&per_cpu(cpuinfo, j);

		if (jcpu->target_freq > max_freq)
			max_freq = jcpu->target_freq;
	}

	if (max_freq != scpu->policy->cur) {
		spin_lock_irqsave(&scaling_cpumask_lock, flags);
		scpu->scaling_freq = max_freq;
		cpumask_set_cpu(scpu->policy->cpu, &scaling_cpumask);
		spin_unlock_irqrestore(&scaling_cpumask_lock, flags);
		wake_up_process(scaling_task);
	}

	return;
}

static void activeffect_mod_timer(struct cpufreq_activeffect_cpuinfo *pcpu)
{
	unsigned long next_timer_rate;

	if (pcpu->target_freq < boost_freq)
		next_timer_rate = timer_rate;
	else
		next_timer_rate = boost_timer_rate;

	mod_timer_pinned(&pcpu->cpu_timer,
			 jiffies + usecs_to_jiffies(next_timer_rate));
}

static void activeffect_add_timer(struct cpufreq_activeffect_cpuinfo *pcpu)
{
	unsigned long next_timer_rate;

	if (pcpu->target_freq < boost_freq)
		next_timer_rate = timer_rate;
	else
		next_timer_rate = boost_timer_rate;

	pcpu->cpu_timer.expires = jiffies + usecs_to_jiffies(next_timer_rate);
	del_timer_sync(&pcpu->cpu_timer);
	add_timer_on(&pcpu->cpu_timer, pcpu->cpu_timer.data);
}

static void cpufreq_activeffect_timer(unsigned long data)
{
	unsigned int delta_idle, delta_wall;
	unsigned int accu_time;
	unsigned int cpu_load;
	unsigned int new_freq;
	unsigned int index;
	unsigned long cur_target_load;
	cputime64_t wall, idle;
	struct cpufreq_activeffect_cpuinfo *pcpu = &per_cpu(cpuinfo, data);

	if (!down_read_trylock(&pcpu->enable_sem))
		return;

	if (!pcpu->governor_enabled)
		goto exit;

	if (cpu_is_offline(data))
		goto exit;

	idle = get_cpu_idle_time(data, &wall);

	delta_idle = (unsigned int)idle - pcpu->prev_cpu_idle;
	delta_wall = (unsigned int)wall - pcpu->prev_cpu_wall;

	accu_time = (wall - pcpu->accu_cpu_wall) * descend_rate;
	pcpu->accu_cpu_wall = wall;
	if (pcpu->prev_cpu_idle + accu_time < pcpu->cpu_idle) {
		pcpu->prev_cpu_idle += accu_time;
		pcpu->prev_cpu_wall += accu_time;
	} else {
		pcpu->prev_cpu_idle = pcpu->cpu_idle;
		pcpu->prev_cpu_wall = pcpu->cpu_wall;
	}

	cpu_load = (delta_wall - delta_idle) * 100 / delta_wall;

	if (pcpu->target_freq < boost_freq)
		cur_target_load = target_load;
	else
		cur_target_load = boost_target_load;

	new_freq = pcpu->target_freq * cpu_load / cur_target_load;

	if (cpufreq_frequency_table_target(pcpu->policy,
					   pcpu->freq_table,
					   new_freq, CPUFREQ_RELATION_L,
					   &index)) {
		pr_warn_once("timer %d: cpufreq_frequency_table_target error\n",
				(int) data);
		goto rearm;
	}

	new_freq = pcpu->freq_table[index].frequency;

	/* Active boost the cpufreq when continuous hit timer */
	pcpu->timer_accu_count++;
	if (active_boost && active_boost == pcpu->timer_accu_count
			 && new_freq < boost_freq)
		new_freq = boost_freq;

	if (new_freq > pcpu->target_freq) {
		pcpu->target_freq = new_freq;
		scaling_freq_update(pcpu);
	}

	if (pcpu->target_freq == pcpu->policy->max)
		goto exit;

rearm:
	activeffect_mod_timer(pcpu);

exit:
	up_read(&pcpu->enable_sem);
	return;
}

static void cpufreq_activeffect_idle_start(void)
{
	unsigned int delta_idle, delta_wall, predict_delta_wall;
	unsigned int cpu_load;
	unsigned int freq;
	unsigned int index;
	unsigned long cur_target_load;
	cputime64_t wall, idle;
	s64 sleep_length;
	int cpu = smp_processor_id();
	struct cpufreq_activeffect_cpuinfo *pcpu = &per_cpu(cpuinfo, cpu);

	if (!down_read_trylock(&pcpu->enable_sem))
		return;

	if (!pcpu->governor_enabled) {
		up_read(&pcpu->enable_sem);
		return;
	}

	del_timer(&pcpu->cpu_timer);

	idle = get_cpu_idle_time(cpu, &wall);
	sleep_length = ktime_to_us(tick_nohz_get_sleep_length());

	delta_idle = (unsigned int)idle - pcpu->prev_cpu_idle;
	delta_wall = (unsigned int)wall - pcpu->prev_cpu_wall;
	predict_delta_wall = delta_wall + sleep_length;

	pcpu->timer_accu_count = 0;

	if (predict_delta_wall >= min_down_duration) {
		pcpu->prev_cpu_idle = idle;
		pcpu->prev_cpu_wall = wall;
		cpu_load = (delta_wall - delta_idle) * 100 / predict_delta_wall;

		if (boost) {
			unsigned int dur;

			dur = ktime_to_ms(ktime_sub(ktime_get(), boost_ktime));
			if (boost <= dur)
				boost = 0;
		}

		if (cpu_load < down_load &&
				pcpu->target_freq != pcpu->policy->min) {
			if (pcpu->target_freq < boost_freq)
				cur_target_load = target_load;
			else
				cur_target_load = boost_target_load;

			freq = pcpu->target_freq * cpu_load / cur_target_load;

			if (cpufreq_frequency_table_target(pcpu->policy,
							pcpu->freq_table,
							freq,
							CPUFREQ_RELATION_L,
							&index))
				goto exit;

			freq = pcpu->freq_table[index].frequency;

			if (boost && freq < boost_freq)
				freq = boost_freq;

			if (freq < pcpu->target_freq) {
				pcpu->target_freq = freq;
				scaling_freq_update(pcpu);
			}
		}
	}

exit:
	up_read(&pcpu->enable_sem);
}

static void cpufreq_activeffect_idle_end(void)
{
	int cpu = smp_processor_id();
	struct cpufreq_activeffect_cpuinfo *pcpu = &per_cpu(cpuinfo, cpu);

	if (!down_read_trylock(&pcpu->enable_sem))
		return;

	if (!pcpu->governor_enabled) {
		up_read(&pcpu->enable_sem);
		return;
	}

	pcpu->cpu_idle = get_cpu_idle_time(cpu, &pcpu->cpu_wall);
	pcpu->accu_cpu_wall = pcpu->cpu_wall;

	if (pcpu->target_freq == pcpu->policy->max)
		goto exit;

	activeffect_mod_timer(pcpu);

exit:
	up_read(&pcpu->enable_sem);
}

static void cpufreq_activeffect_boost(void)
{
	int i;
	int anyboost = 0;
	unsigned long flags;
	struct cpufreq_activeffect_cpuinfo *pcpu;

	spin_lock_irqsave(&scaling_cpumask_lock, flags);

	for_each_online_cpu(i) {
		pcpu = &per_cpu(cpuinfo, i);
		if (pcpu->target_freq < boost_freq)
			pcpu->target_freq = boost_freq;

		if (pcpu->scaling_freq && pcpu->scaling_freq < boost_freq) {
			pcpu->scaling_freq = boost_freq;
			cpumask_set_cpu(i, &scaling_cpumask);
			anyboost = 1;
		}
	}

	spin_unlock_irqrestore(&scaling_cpumask_lock, flags);

	if (anyboost)
		wake_up_process(scaling_task);
}

static int cpufreq_activeffect_scaling_task(void *data)
{
	unsigned int cpu;
	cpumask_t tmp_mask;
	unsigned long flags;
	struct cpufreq_activeffect_cpuinfo *pcpu;

	while (1) {
		set_current_state(TASK_INTERRUPTIBLE);
		spin_lock_irqsave(&scaling_cpumask_lock, flags);
		if (cpumask_empty(&scaling_cpumask)) {
			spin_unlock_irqrestore(&scaling_cpumask_lock, flags);
			schedule();
			if (kthread_should_stop())
				break;
			spin_lock_irqsave(&scaling_cpumask_lock, flags);
		}

		set_current_state(TASK_RUNNING);
		tmp_mask = scaling_cpumask;
		cpumask_clear(&scaling_cpumask);
		spin_unlock_irqrestore(&scaling_cpumask_lock, flags);

		for_each_cpu(cpu, &tmp_mask) {
			pcpu = &per_cpu(cpuinfo, cpu);
			if (!down_read_trylock(&pcpu->enable_sem))
				continue;
			if (!pcpu->governor_enabled) {
				up_read(&pcpu->enable_sem);
				continue;
			}

			if (pcpu->scaling_freq != pcpu->policy->cur)
				__cpufreq_driver_target(pcpu->policy,
							pcpu->scaling_freq,
							CPUFREQ_RELATION_L);

			up_read(&pcpu->enable_sem);
		}

	}

	return 0;
}


/* attribute */
static ssize_t show_timer_rate(struct kobject *kobj,
			struct attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%lu\n", timer_rate);
}

static ssize_t store_timer_rate(struct kobject *kobj,
			struct attribute *attr, const char *buf, size_t count)
{
	int ret;
	unsigned long val;

	ret = kstrtoul(buf, 0, &val);
	if (ret < 0)
		return ret;
	timer_rate = val;
	return count;
}

static struct global_attr timer_rate_attr = __ATTR(timer_rate, 0644,
			show_timer_rate, store_timer_rate);

static ssize_t show_boost_timer_rate(struct kobject *kobj,
			struct attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%lu\n", boost_timer_rate);
}

static ssize_t store_boost_timer_rate(struct kobject *kobj,
			struct attribute *attr, const char *buf, size_t count)
{
	int ret;
	unsigned long val;

	ret = kstrtoul(buf, 0, &val);
	if (ret < 0)
		return ret;
	boost_timer_rate = val;
	return count;
}

static struct global_attr boost_timer_rate_attr = __ATTR(boost_timer_rate, 0644,
			show_boost_timer_rate, store_boost_timer_rate);

static ssize_t show_target_load(struct kobject *kobj,
			struct attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u\n", target_load);
}

static ssize_t store_target_load(struct kobject *kobj,
			struct attribute *attr, const char *buf, size_t count)
{
	int ret;
	unsigned long val;

	ret = kstrtoul(buf, 0, &val);
	if (ret < 0)
		return ret;
	target_load = val;
	return count;
}

static struct global_attr target_load_attr = __ATTR(target_load, 0644,
		show_target_load, store_target_load);

static ssize_t show_boost_target_load(struct kobject *kobj,
			struct attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u\n", boost_target_load);
}

static ssize_t store_boost_target_load(struct kobject *kobj,
			struct attribute *attr, const char *buf, size_t count)
{
	int ret;
	unsigned long val;

	ret = kstrtoul(buf, 0, &val);
	if (ret < 0)
		return ret;
	boost_target_load = val;
	return count;
}

static struct global_attr boost_target_load_attr = __ATTR(
		boost_target_load, 0644,
		show_boost_target_load, store_boost_target_load);


static ssize_t show_boost_freq(struct kobject *kobj,
			struct attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u\n", boost_freq);
}

static ssize_t store_boost_freq(struct kobject *kobj,
			struct attribute *attr, const char *buf, size_t count)
{
	int ret;
	unsigned long val;

	ret = kstrtoul(buf, 0, &val);
	if (ret < 0)
		return ret;
	boost_freq = val;
	return count;
}

static struct global_attr boost_freq_attr = __ATTR(boost_freq, 0644,
		show_boost_freq, store_boost_freq);

static ssize_t show_boost(struct kobject *kobj,
			struct attribute *attr, char *buf)
{
	int left_boost = 0;

	if (boost) {
		left_boost = boost - ktime_to_ms(ktime_sub(ktime_get(),
							   boost_ktime));
		if (left_boost < 0)
			left_boost = 0;
	}

	return snprintf(buf, PAGE_SIZE, "%u\n", left_boost);
}

static ssize_t store_boost(struct kobject *kobj,
			struct attribute *attr, const char *buf, size_t count)
{
	int ret;
	unsigned long val;

	ret = kstrtoul(buf, 0, &val);
	if (ret < 0)
		return ret;

	boost = val;
	if (boost > 0) {
		boost_ktime = ktime_get();
		cpufreq_activeffect_boost();
	}

	return count;
}

static struct global_attr boost_attr = __ATTR(boost, 0644,
		show_boost, store_boost);

static ssize_t show_active_boost(struct kobject *kobj,
			struct attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u\n", active_boost);
}

static ssize_t store_active_boost(struct kobject *kobj,
			struct attribute *attr, const char *buf, size_t count)
{
	int ret;
	unsigned long val;

	ret = kstrtoul(buf, 0, &val);
	if (ret < 0)
		return ret;
	active_boost = val;
	return count;
}

static struct global_attr active_boost_attr = __ATTR(active_boost, 0644,
		show_active_boost, store_active_boost);

static ssize_t show_min_down_duration(struct kobject *kobj,
			struct attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%lu\n", min_down_duration);
}

static ssize_t store_min_down_duration(struct kobject *kobj,
			struct attribute *attr, const char *buf, size_t count)
{
	int ret;
	unsigned long val;

	ret = kstrtoul(buf, 0, &val);
	if (ret < 0)
		return ret;
	min_down_duration = val;
	return count;
}

static struct global_attr min_down_duration_attr = __ATTR(
		min_down_duration, 0644,
		show_min_down_duration, store_min_down_duration);

static ssize_t show_down_load(struct kobject *kobj,
			struct attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u\n", down_load);
}

static ssize_t store_down_load(struct kobject *kobj,
			struct attribute *attr, const char *buf, size_t count)
{
	int ret;
	unsigned long val;

	ret = kstrtoul(buf, 0, &val);
	if (ret < 0)
		return ret;
	down_load = val;
	return count;
}

static struct global_attr down_load_attr = __ATTR(down_load, 0644,
		show_down_load, store_down_load);

static ssize_t show_io_is_busy(struct kobject *kobj,
			struct attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u\n", io_is_busy);
}

static ssize_t store_io_is_busy(struct kobject *kobj,
			struct attribute *attr, const char *buf, size_t count)
{
	int ret;
	unsigned long val;

	ret = kstrtoul(buf, 0, &val);
	if (ret < 0)
		return ret;
	io_is_busy = val;
	return count;
}

static struct global_attr io_is_busy_attr = __ATTR(io_is_busy, 0644,
		show_io_is_busy, store_io_is_busy);

static ssize_t show_descend_rate(struct kobject *kobj,
			struct attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u\n", descend_rate);
}

static ssize_t store_descend_rate(struct kobject *kobj,
			struct attribute *attr, const char *buf, size_t count)
{
	int ret;
	unsigned long val;

	ret = kstrtoul(buf, 0, &val);
	if (ret < 0)
		return ret;
	descend_rate = val;
	return count;
}

static struct global_attr descend_rate_attr = __ATTR(descend_rate, 0644,
		show_descend_rate, store_descend_rate);

static struct attribute *activeffect_attributes[] = {
	&timer_rate_attr.attr,
	&target_load_attr.attr,
	&boost_timer_rate_attr.attr,
	&boost_target_load_attr.attr,
	&boost_freq_attr.attr,
	&boost_attr.attr,
	&active_boost_attr.attr,
	&min_down_duration_attr.attr,
	&down_load_attr.attr,
	&io_is_busy_attr.attr,
	&descend_rate_attr.attr,
	NULL,
};

static struct attribute_group activeffect_attr_group = {
	.attrs = activeffect_attributes,
	.name = "activeffect",
};

static int cpufreq_activeffect_idle_notifier(struct notifier_block *nb,
					     unsigned long val,
					     void *data)
{
	switch (val) {
	case IDLE_START:
		cpufreq_activeffect_idle_start();
		break;
	case IDLE_END:
		cpufreq_activeffect_idle_end();
		break;
	}

	return 0;
}
static struct notifier_block cpufreq_activeffect_idle_nb = {
	.notifier_call = cpufreq_activeffect_idle_notifier,
};

static int cpufreq_governor_activeffect(struct cpufreq_policy *policy,
					unsigned int event)
{
	int rc;
	unsigned int j;
	unsigned int cpu = policy->cpu;
	struct cpufreq_frequency_table *freq_table;
	struct cpufreq_activeffect_cpuinfo *pcpu;

	switch (event) {
	case CPUFREQ_GOV_START:
		if ((!cpu_online(cpu)) || (!policy->cur))
			return -EINVAL;

		mutex_lock(&gov_mutex);

		freq_table = cpufreq_frequency_get_table(cpu);

		gov_enable++;

		pcpu = &per_cpu(cpuinfo, cpu);
		pcpu->scaling_freq = policy->cur;

		if (!boost_freq)
			boost_freq = policy->max;

		for_each_cpu(j, policy->cpus) {
			pcpu = &per_cpu(cpuinfo, j);
			pcpu->policy = policy;
			pcpu->freq_table = freq_table;
			pcpu->target_freq = policy->cur;
			pcpu->max_freq = policy->max;
			pcpu->timer_accu_count = 0;
			pcpu->cpu_idle = get_cpu_idle_time(j, &pcpu->cpu_wall);
			pcpu->prev_cpu_idle = pcpu->cpu_idle;
			pcpu->prev_cpu_wall = pcpu->cpu_wall;
			pcpu->accu_cpu_wall = pcpu->cpu_wall;
			down_write(&pcpu->enable_sem);
			if (cpu_online(j))
				activeffect_add_timer(pcpu);
			pcpu->governor_enabled = 1;
			up_write(&pcpu->enable_sem);
		}

		/*
		 * Start the timerschedule work, when this governor
		 * is used for first time
		 */
		if (gov_enable == 1) {
			rc = sysfs_create_group(cpufreq_global_kobject,
						&activeffect_attr_group);
			if (rc) {
				mutex_unlock(&gov_mutex);
				return rc;
			}

			idle_notifier_register(&cpufreq_activeffect_idle_nb);
		}

		mutex_unlock(&gov_mutex);

		break;
	case CPUFREQ_GOV_STOP:
		mutex_lock(&gov_mutex);

		gov_enable--;

		for_each_cpu(j, policy->cpus) {
			pcpu = &per_cpu(cpuinfo, j);
			down_write(&pcpu->enable_sem);
			pcpu->policy = NULL;
			pcpu->timer_accu_count = 0;
			pcpu->governor_enabled = 0;
			del_timer_sync(&pcpu->cpu_timer);
			up_write(&pcpu->enable_sem);
		}

		if (!gov_enable) {
			sysfs_remove_group(cpufreq_global_kobject,
					   &activeffect_attr_group);
			idle_notifier_unregister(&cpufreq_activeffect_idle_nb);
		}

		mutex_unlock(&gov_mutex);
		break;
	case CPUFREQ_GOV_LIMITS:
		mutex_lock(&gov_mutex);
		if (policy->max < policy->cur)
			__cpufreq_driver_target(policy,
					policy->max, CPUFREQ_RELATION_H);
		else if (policy->min > policy->cur)
			__cpufreq_driver_target(policy,
					policy->min, CPUFREQ_RELATION_L);

		/* Update target_freq due to new gov limits */
		for_each_cpu(j, policy->cpus) {
			if (cpu_is_offline(j))
				continue;

			pcpu = &per_cpu(cpuinfo, j);

			/* hold write semaphore to avoid race */
			down_write(&pcpu->enable_sem);
			if (pcpu->governor_enabled == 0) {
				up_write(&pcpu->enable_sem);
				continue;
			}

			/* update target_freq firstly */
			if (policy->max < pcpu->target_freq)
				pcpu->target_freq = policy->max;
			else if (policy->min > pcpu->target_freq)
				pcpu->target_freq = policy->min;

			activeffect_add_timer(pcpu);
			up_write(&pcpu->enable_sem);
		}
		mutex_unlock(&gov_mutex);
		break;
	default:
		break;
	}
	return 0;
}

static int __init cpufreq_gov_activeffect_init(void)
{
	unsigned int i;
	struct cpufreq_activeffect_cpuinfo *pcpu;
	struct sched_param param = { .sched_priority = MAX_RT_PRIO-1 };

	/* Initalize per-cpu timers */
	for_each_possible_cpu(i) {
		pcpu = &per_cpu(cpuinfo, i);
		init_timer_deferrable(&pcpu->cpu_timer);
		pcpu->cpu_timer.function = cpufreq_activeffect_timer;
		pcpu->cpu_timer.data = i;
		init_rwsem(&pcpu->enable_sem);
	}

	spin_lock_init(&scaling_cpumask_lock);
	mutex_init(&gov_mutex);

	scaling_task =
		kthread_create(cpufreq_activeffect_scaling_task, NULL,
				"kcpufreq_activeffect_scaling");
	if (IS_ERR(scaling_task))
		return PTR_ERR(scaling_task);

	sched_setscheduler_nocheck(scaling_task, SCHED_FIFO, &param);
	get_task_struct(scaling_task);

	/* wake up so the thread does not look hung to the freezer */
	wake_up_process(scaling_task);

	return cpufreq_register_governor(&cpufreq_gov_activeffect);
}


static void __exit cpufreq_gov_activeffect_exit(void)
{
	cpufreq_unregister_governor(&cpufreq_gov_activeffect);
	kthread_stop(scaling_task);
	put_task_struct(scaling_task);
}


MODULE_AUTHOR("Lianwei Wang <lian-wei.wang@motorola.com>");
MODULE_DESCRIPTION("CPUfreq policy governor 'activeffect'");
MODULE_LICENSE("GPL");

#ifdef CONFIG_CPU_FREQ_DEFAULT_GOV_ACTIVEFFECT
fs_initcall(cpufreq_gov_activeffect_init);
#else
module_init(cpufreq_gov_activeffect_init);
#endif
module_exit(cpufreq_gov_activeffect_exit);
