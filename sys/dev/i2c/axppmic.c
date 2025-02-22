/* $NetBSD: axppmic.c,v 1.24 2019/05/28 20:22:18 jmcneill Exp $ */

/*-
 * Copyright (c) 2014-2018 Jared McNeill <jmcneill@invisible.ca>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: axppmic.c,v 1.24 2019/05/28 20:22:18 jmcneill Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/device.h>
#include <sys/conf.h>
#include <sys/bus.h>
#include <sys/kmem.h>

#include <dev/i2c/i2cvar.h>

#include <dev/sysmon/sysmonvar.h>
#include <dev/sysmon/sysmon_taskq.h>

#include <dev/fdt/fdtvar.h>

#define	AXP_POWER_SOURCE_REG	0x00
#define	 AXP_POWER_SOURCE_ACIN_PRESENT	__BIT(7)
#define	 AXP_POWER_SOURCE_VBUS_PRESENT	__BIT(5)
#define	 AXP_POWER_SOURCE_CHARGE_DIRECTION __BIT(2)

#define	AXP_POWER_MODE_REG	0x01
#define	 AXP_POWER_MODE_BATT_VALID	__BIT(4)
#define	 AXP_POWER_MODE_BATT_PRESENT	__BIT(5)
#define	 AXP_POWER_MODE_BATT_CHARGING	__BIT(6)

#define	AXP_CHIP_ID_REG		0x03

#define AXP_POWER_DISABLE_REG	0x32
#define	 AXP_POWER_DISABLE_CTRL	__BIT(7)

#define AXP_IRQ_ENABLE_REG(n)	(0x40 + (n) - 1)
#define	 AXP_IRQ1_ACIN_RAISE	__BIT(6)
#define	 AXP_IRQ1_ACIN_LOWER	__BIT(5)
#define	 AXP_IRQ1_VBUS_RAISE	__BIT(3)
#define	 AXP_IRQ1_VBUS_LOWER	__BIT(2)
#define AXP_IRQ_STATUS_REG(n)	(0x48 + (n) - 1)

#define	AXP_BATSENSE_HI_REG	0x78
#define	AXP_BATSENSE_LO_REG	0x79

#define	AXP_BATTCHG_HI_REG	0x7a
#define	AXP_BATTCHG_LO_REG	0x7b

#define	AXP_BATTDISCHG_HI_REG	0x7c
#define	AXP_BATTDISCHG_LO_REG	0x7d

#define	AXP_ADC_RAW(_hi, _lo)	\
	(((u_int)(_hi) << 4) | ((_lo) & 0xf))

#define	AXP_FUEL_GAUGE_CTRL_REG	0xb8
#define	 AXP_FUEL_GAUGE_CTRL_EN	__BIT(7)

#define	AXP_BATT_CAP_REG	0xb9
#define	 AXP_BATT_CAP_VALID	__BIT(7)
#define	 AXP_BATT_CAP_PERCENT	__BITS(6,0)

#define	AXP_BATT_MAX_CAP_HI_REG	0xe0
#define	 AXP_BATT_MAX_CAP_VALID	__BIT(7)
#define	AXP_BATT_MAX_CAP_LO_REG	0xe1

#define	AXP_BATT_COULOMB_HI_REG	0xe2
#define	 AXP_BATT_COULOMB_VALID	__BIT(7)
#define	AXP_BATT_COULOMB_LO_REG	0xe3

#define	AXP_COULOMB_RAW(_hi, _lo)	\
	(((u_int)(_hi & ~__BIT(7)) << 8) | (_lo))

#define	AXP_BATT_CAP_WARN_REG	0xe6
#define	 AXP_BATT_CAP_WARN_LV1	__BITS(7,4)
#define	 AXP_BATT_CAP_WARN_LV2	__BITS(3,0)

#define	AXP_ADDR_EXT_REG	0xff	/* AXP806 */
#define	 AXP_ADDR_EXT_MASTER	0
#define	 AXP_ADDR_EXT_SLAVE	__BIT(4)

struct axppmic_ctrl {
	device_t	c_dev;

	const char *	c_name;
	u_int		c_min;
	u_int		c_max;
	u_int		c_step1;
	u_int		c_step1cnt;
	u_int		c_step2;
	u_int		c_step2cnt;
	u_int		c_step2start;

	uint8_t		c_enable_reg;
	uint8_t		c_enable_mask;
	uint8_t		c_enable_val;
	uint8_t		c_disable_val;

	uint8_t		c_voltage_reg;
	uint8_t		c_voltage_mask;
};

#define AXP_CTRL(name, min, max, step, ereg, emask, vreg, vmask)	\
	{ .c_name = (name), .c_min = (min), .c_max = (max),		\
	  .c_step1 = (step), .c_step1cnt = (((max) - (min)) / (step)) + 1, \
	  .c_step2 = 0, .c_step2cnt = 0,				\
	  .c_enable_reg = (ereg), .c_enable_mask = (emask),		\
	  .c_enable_val = (emask), .c_disable_val = 0,			\
	  .c_voltage_reg = (vreg), .c_voltage_mask = (vmask) }

#define AXP_CTRL2(name, min, max, step1, step1cnt, step2, step2cnt, ereg, emask, vreg, vmask) \
	{ .c_name = (name), .c_min = (min), .c_max = (max),		\
	  .c_step1 = (step1), .c_step1cnt = (step1cnt),			\
	  .c_step2 = (step2), .c_step2cnt = (step2cnt),			\
	  .c_enable_reg = (ereg), .c_enable_mask = (emask),		\
	  .c_enable_val = (emask), .c_disable_val = 0,			\
	  .c_voltage_reg = (vreg), .c_voltage_mask = (vmask) }

#define AXP_CTRL2_RANGE(name, min, max, step1, step1cnt, step2start, step2, step2cnt, ereg, emask, vreg, vmask) \
	{ .c_name = (name), .c_min = (min), .c_max = (max),		\
	  .c_step1 = (step1), .c_step1cnt = (step1cnt),			\
	  .c_step2start = (step2start),					\
	  .c_step2 = (step2), .c_step2cnt = (step2cnt),			\
	  .c_enable_reg = (ereg), .c_enable_mask = (emask),		\
	  .c_enable_val = (emask), .c_disable_val = 0,			\
	  .c_voltage_reg = (vreg), .c_voltage_mask = (vmask) }

#define AXP_CTRL_IO(name, min, max, step, ereg, emask, eval, dval, vreg, vmask)	\
	{ .c_name = (name), .c_min = (min), .c_max = (max),		\
	  .c_step1 = (step), .c_step1cnt = (((max) - (min)) / (step)) + 1, \
	  .c_step2 = 0, .c_step2cnt = 0,				\
	  .c_enable_reg = (ereg), .c_enable_mask = (emask),		\
	  .c_enable_val = (eval), .c_disable_val = (dval),		\
	  .c_voltage_reg = (vreg), .c_voltage_mask = (vmask) }

#define AXP_CTRL_SW(name, ereg, emask)					\
	{ .c_name = (name), 						\
	  .c_enable_reg = (ereg), .c_enable_mask = (emask),		\
	  .c_enable_val = (emask), .c_disable_val = 0 }

static const struct axppmic_ctrl axp803_ctrls[] = {
	AXP_CTRL("dldo1", 700, 3300, 100,
		0x12, __BIT(3), 0x15, __BITS(4,0)),
	AXP_CTRL2("dldo2", 700, 4200, 100, 28, 200, 4,
		0x12, __BIT(4), 0x16, __BITS(4,0)),
	AXP_CTRL("dldo3", 700, 3300, 100,
	 	0x12, __BIT(5), 0x17, __BITS(4,0)),
	AXP_CTRL("dldo4", 700, 3300, 100,
		0x12, __BIT(6), 0x18, __BITS(4,0)),
	AXP_CTRL("eldo1", 700, 1900, 50,
		0x12, __BIT(0), 0x19, __BITS(4,0)),
	AXP_CTRL("eldo2", 700, 1900, 50,
		0x12, __BIT(1), 0x1a, __BITS(4,0)),
	AXP_CTRL("eldo3", 700, 1900, 50,
		0x12, __BIT(2), 0x1b, __BITS(4,0)),
	AXP_CTRL("fldo1", 700, 1450, 50,
		0x13, __BIT(2), 0x1c, __BITS(3,0)),
	AXP_CTRL("fldo2", 700, 1450, 50,
		0x13, __BIT(3), 0x1d, __BITS(3,0)),
	AXP_CTRL("dcdc1", 1600, 3400, 100,
		0x10, __BIT(0), 0x20, __BITS(4,0)),
	AXP_CTRL2("dcdc2", 500, 1300, 10, 70, 20, 5,
		0x10, __BIT(1), 0x21, __BITS(6,0)),
	AXP_CTRL2("dcdc3", 500, 1300, 10, 70, 20, 5,
		0x10, __BIT(2), 0x22, __BITS(6,0)),
	AXP_CTRL2("dcdc4", 500, 1300, 10, 70, 20, 5,
		0x10, __BIT(3), 0x23, __BITS(6,0)),
	AXP_CTRL2("dcdc5", 800, 1840, 10, 33, 20, 36,
		0x10, __BIT(4), 0x24, __BITS(6,0)),
	AXP_CTRL2("dcdc6", 600, 1520, 10, 51, 20, 21,
		0x10, __BIT(5), 0x25, __BITS(6,0)),
	AXP_CTRL("aldo1", 700, 3300, 100,
		0x13, __BIT(5), 0x28, __BITS(4,0)),
	AXP_CTRL("aldo2", 700, 3300, 100,
		0x13, __BIT(6), 0x29, __BITS(4,0)),
	AXP_CTRL("aldo3", 700, 3300, 100,
		0x13, __BIT(7), 0x2a, __BITS(4,0)),
};

static const struct axppmic_ctrl axp805_ctrls[] = {
	AXP_CTRL2("dcdca", 600, 1520, 10, 51, 20, 21,
		0x10, __BIT(0), 0x12, __BITS(6,0)),
	AXP_CTRL("dcdcb", 1000, 2550, 50,
		0x10, __BIT(1), 0x13, __BITS(4,0)),
	AXP_CTRL2("dcdcc", 600, 1520, 10, 51, 20, 21,
		0x10, __BIT(2), 0x14, __BITS(6,0)),
	AXP_CTRL2("dcdcd", 600, 3300, 20, 46, 100, 18,
		0x10, __BIT(3), 0x15, __BITS(5,0)),
	AXP_CTRL("dcdce", 1100, 3400, 100,
		0x10, __BIT(4), 0x16, __BITS(4,0)),
	AXP_CTRL("aldo1", 700, 3300, 100,
		0x10, __BIT(5), 0x17, __BITS(4,0)),
	AXP_CTRL("aldo2", 700, 3400, 100,
		0x10, __BIT(6), 0x18, __BITS(4,0)),
	AXP_CTRL("aldo3", 700, 3300, 100,
		0x10, __BIT(7), 0x19, __BITS(4,0)),
	AXP_CTRL("bldo1", 700, 1900, 100,
		0x11, __BIT(0), 0x20, __BITS(3,0)),
	AXP_CTRL("bldo2", 700, 1900, 100,
		0x11, __BIT(1), 0x21, __BITS(3,0)),
	AXP_CTRL("bldo3", 700, 1900, 100,
		0x11, __BIT(2), 0x22, __BITS(3,0)),
	AXP_CTRL("bldo4", 700, 1900, 100,
		0x11, __BIT(3), 0x23, __BITS(3,0)),
	AXP_CTRL("cldo1", 700, 3300, 100, 
		0x11, __BIT(4), 0x24, __BITS(4,0)),
	AXP_CTRL2("cldo2", 700, 4200, 100, 28, 200, 4,
		0x11, __BIT(5), 0x25, __BITS(4,0)),
	AXP_CTRL("cldo3", 700, 3300, 100, 
		0x11, __BIT(6), 0x26, __BITS(4,0)),
};

static const struct axppmic_ctrl axp809_ctrls[] = {
	AXP_CTRL("dc5ldo", 700, 1400, 100,
		0x10, __BIT(0), 0x1c, __BITS(2,0)),
	AXP_CTRL("dcdc1", 1600, 3400, 100,
		0x10, __BIT(1), 0x21, __BITS(4,0)),
	AXP_CTRL("dcdc2", 600, 1540, 20,
		0x10, __BIT(2), 0x22, __BITS(5,0)),
	AXP_CTRL("dcdc3", 600, 1860, 20,
		0x10, __BIT(3), 0x23, __BITS(5,0)),
	AXP_CTRL2_RANGE("dcdc4", 600, 2600, 20, 47, 1800, 100, 9,
		0x10, __BIT(4), 0x24, __BITS(5,0)),
	AXP_CTRL("dcdc5", 1000, 2550, 50,
		0x10, __BIT(5), 0x25, __BITS(4,0)),
	AXP_CTRL("aldo1", 700, 3300, 100,
		0x10, __BIT(6), 0x28, __BITS(4,0)),
	AXP_CTRL("aldo2", 700, 3300, 100,
		0x10, __BIT(7), 0x29, __BITS(4,0)),
	AXP_CTRL("eldo1", 700, 3300, 100,
		0x12, __BIT(0), 0x19, __BITS(4,0)),
	AXP_CTRL("eldo2", 700, 3300, 100,
		0x12, __BIT(1), 0x1a, __BITS(4,0)),
	AXP_CTRL("eldo3", 700, 3300, 100,
		0x12, __BIT(2), 0x1b, __BITS(4,0)),
	AXP_CTRL2_RANGE("dldo1", 700, 4000, 100, 26, 3400, 200, 4,
		0x12, __BIT(3), 0x15, __BITS(4,0)),
	AXP_CTRL("dldo2", 700, 3300, 100,
		0x12, __BIT(4), 0x16, __BITS(4,0)),
	AXP_CTRL("aldo3", 700, 3300, 100,
		0x12, __BIT(5), 0x2a, __BITS(4,0)),
	AXP_CTRL_SW("sw",
		0x12, __BIT(6)),
	/* dc1sw is another switch for dcdc1 */
	AXP_CTRL("dc1sw", 1600, 3400, 100,
		0x12, __BIT(7), 0x21, __BITS(4,0)),
	AXP_CTRL_IO("ldo_io0", 700, 3300, 100,
		0x90, __BITS(3,0), 0x3, 0x7, 0x91, __BITS(4,0)),
	AXP_CTRL_IO("ldo_io1", 700, 3300, 100,
		0x92, __BITS(3,0), 0x3, 0x7, 0x93, __BITS(4,0)),
};

static const struct axppmic_ctrl axp813_ctrls[] = {
	AXP_CTRL("dldo1", 700, 3300, 100,
		0x12, __BIT(3), 0x15, __BITS(4,0)),
	AXP_CTRL2("dldo2", 700, 4200, 100, 28, 200, 4,
		0x12, __BIT(4), 0x16, __BITS(4,0)),
	AXP_CTRL("dldo3", 700, 3300, 100,
	 	0x12, __BIT(5), 0x17, __BITS(4,0)),
	AXP_CTRL("dldo4", 700, 3300, 100,
		0x12, __BIT(6), 0x18, __BITS(4,0)),
	AXP_CTRL("eldo1", 700, 1900, 50,
		0x12, __BIT(0), 0x19, __BITS(4,0)),
	AXP_CTRL("eldo2", 700, 1900, 50,
		0x12, __BIT(1), 0x1a, __BITS(4,0)),
	AXP_CTRL("eldo3", 700, 1900, 50,
		0x12, __BIT(2), 0x1b, __BITS(4,0)),
	AXP_CTRL("fldo1", 700, 1450, 50,
		0x13, __BIT(2), 0x1c, __BITS(3,0)),
	AXP_CTRL("fldo2", 700, 1450, 50,
		0x13, __BIT(3), 0x1d, __BITS(3,0)),
	AXP_CTRL("dcdc1", 1600, 3400, 100,
		0x10, __BIT(0), 0x20, __BITS(4,0)),
	AXP_CTRL2("dcdc2", 500, 1300, 10, 70, 20, 5,
		0x10, __BIT(1), 0x21, __BITS(6,0)),
	AXP_CTRL2("dcdc3", 500, 1300, 10, 70, 20, 5,
		0x10, __BIT(2), 0x22, __BITS(6,0)),
	AXP_CTRL2("dcdc4", 500, 1300, 10, 70, 20, 5,
		0x10, __BIT(3), 0x23, __BITS(6,0)),
	AXP_CTRL2("dcdc5", 800, 1840, 10, 33, 20, 36,
		0x10, __BIT(4), 0x24, __BITS(6,0)),
	AXP_CTRL2("dcdc6", 600, 1520, 10, 51, 20, 21,
		0x10, __BIT(5), 0x25, __BITS(6,0)),
	AXP_CTRL2("dcdc7", 600, 1520, 10, 51, 20, 21,
		0x10, __BIT(6), 0x26, __BITS(6,0)),
	AXP_CTRL("aldo1", 700, 3300, 100,
		0x13, __BIT(5), 0x28, __BITS(4,0)),
	AXP_CTRL("aldo2", 700, 3300, 100,
		0x13, __BIT(6), 0x29, __BITS(4,0)),
	AXP_CTRL("aldo3", 700, 3300, 100,
		0x13, __BIT(7), 0x2a, __BITS(4,0)),
};

struct axppmic_irq {
	u_int reg;
	uint8_t mask;
};

#define	AXPPMIC_IRQ(_reg, _mask)	\
	{ .reg = (_reg), .mask = (_mask) }

struct axppmic_config {
	const char *name;
	const struct axppmic_ctrl *controls;
	u_int ncontrols;
	u_int irq_regs;
	bool has_battery;
	bool has_fuel_gauge;
	bool has_mode_set;
	struct axppmic_irq poklirq;
	struct axppmic_irq acinirq;
	struct axppmic_irq vbusirq;
	struct axppmic_irq battirq;
	struct axppmic_irq chargeirq;
	struct axppmic_irq chargestirq;
	u_int batsense_step;	/* uV */
	u_int charge_step;	/* uA */
	u_int discharge_step;	/* uA */
	u_int maxcap_step;	/* uAh */
	u_int coulomb_step;	/* uAh */
};

enum axppmic_sensor {
	AXP_SENSOR_ACIN_PRESENT,
	AXP_SENSOR_VBUS_PRESENT,
	AXP_SENSOR_BATT_PRESENT,
	AXP_SENSOR_BATT_CHARGING,
	AXP_SENSOR_BATT_CHARGE_STATE,
	AXP_SENSOR_BATT_VOLTAGE,
	AXP_SENSOR_BATT_CHARGE_CURRENT,
	AXP_SENSOR_BATT_DISCHARGE_CURRENT,
	AXP_SENSOR_BATT_CAPACITY_PERCENT,
	AXP_SENSOR_BATT_MAXIMUM_CAPACITY,
	AXP_SENSOR_BATT_CURRENT_CAPACITY,
	AXP_NSENSORS
};

struct axppmic_softc {
	device_t	sc_dev;
	i2c_tag_t	sc_i2c;
	i2c_addr_t	sc_addr;
	int		sc_phandle;

	const struct axppmic_config *sc_conf;

	struct sysmon_pswitch sc_smpsw;

	struct sysmon_envsys *sc_sme;

	envsys_data_t	sc_sensor[AXP_NSENSORS];

	u_int		sc_warn_thres;
	u_int		sc_shut_thres;
};

struct axpreg_softc {
	device_t	sc_dev;
	i2c_tag_t	sc_i2c;
	i2c_addr_t	sc_addr;
	const struct axppmic_ctrl *sc_ctrl;
};

struct axpreg_attach_args {
	const struct axppmic_ctrl *reg_ctrl;
	int		reg_phandle;
	i2c_tag_t	reg_i2c;
	i2c_addr_t	reg_addr;
};

static const struct axppmic_config axp803_config = {
	.name = "AXP803",
	.controls = axp803_ctrls,
	.ncontrols = __arraycount(axp803_ctrls),
	.irq_regs = 6,
	.has_battery = true,
	.has_fuel_gauge = true,
	.batsense_step = 1100,
	.charge_step = 1000,
	.discharge_step = 1000,
	.maxcap_step = 1456,
	.coulomb_step = 1456,
	.poklirq = AXPPMIC_IRQ(5, __BIT(3)),
	.acinirq = AXPPMIC_IRQ(1, __BITS(6,5)),
	.vbusirq = AXPPMIC_IRQ(1, __BITS(3,2)),
	.battirq = AXPPMIC_IRQ(2, __BITS(7,6)),
	.chargeirq = AXPPMIC_IRQ(2, __BITS(3,2)),
	.chargestirq = AXPPMIC_IRQ(4, __BITS(1,0)),	
};

static const struct axppmic_config axp805_config = {
	.name = "AXP805",
	.controls = axp805_ctrls,
	.ncontrols = __arraycount(axp805_ctrls),
	.irq_regs = 2,
	.poklirq = AXPPMIC_IRQ(2, __BIT(0)),
};

static const struct axppmic_config axp806_config = {
	.name = "AXP806",
	.controls = axp805_ctrls,
	.ncontrols = __arraycount(axp805_ctrls),
#if notyet
	.irq_regs = 2,
	.poklirq = AXPPMIC_IRQ(2, __BIT(0)),
#endif
	.has_mode_set = true,
};

static const struct axppmic_config axp809_config = {
	.name = "AXP809",
	.controls = axp809_ctrls,
	.ncontrols = __arraycount(axp809_ctrls),
};

static const struct axppmic_config axp813_config = {
	.name = "AXP813",
	.controls = axp813_ctrls,
	.ncontrols = __arraycount(axp813_ctrls),
	.irq_regs = 6,
	.has_battery = true,
	.has_fuel_gauge = true,
	.batsense_step = 1100,
	.charge_step = 1000,
	.discharge_step = 1000,
	.maxcap_step = 1456,
	.coulomb_step = 1456,
	.poklirq = AXPPMIC_IRQ(5, __BIT(3)),
	.acinirq = AXPPMIC_IRQ(1, __BITS(6,5)),
	.vbusirq = AXPPMIC_IRQ(1, __BITS(3,2)),
	.battirq = AXPPMIC_IRQ(2, __BITS(7,6)),
	.chargeirq = AXPPMIC_IRQ(2, __BITS(3,2)),
	.chargestirq = AXPPMIC_IRQ(4, __BITS(1,0)),	
};

static const struct device_compatible_entry compat_data[] = {
	{ "x-powers,axp803",		(uintptr_t)&axp803_config },
	{ "x-powers,axp805",		(uintptr_t)&axp805_config },
	{ "x-powers,axp806",		(uintptr_t)&axp806_config },
	{ "x-powers,axp809",		(uintptr_t)&axp809_config },
	{ "x-powers,axp813",		(uintptr_t)&axp813_config },
	{ NULL,				0 }
};

static int
axppmic_read(i2c_tag_t tag, i2c_addr_t addr, uint8_t reg, uint8_t *val, int flags)
{
	return iic_smbus_read_byte(tag, addr, reg, val, flags);
}

static int
axppmic_write(i2c_tag_t tag, i2c_addr_t addr, uint8_t reg, uint8_t val, int flags)
{
	return iic_smbus_write_byte(tag, addr, reg, val, flags);
}

static int
axppmic_set_voltage(i2c_tag_t tag, i2c_addr_t addr, const struct axppmic_ctrl *c, u_int min, u_int max)
{
	const int flags = (cold ? I2C_F_POLL : 0);
	u_int vol, reg_val;
	int nstep, error;
	uint8_t val;

	if (!c->c_voltage_mask)
		return EINVAL;

	if (min < c->c_min || min > c->c_max)
		return EINVAL;

	reg_val = 0;
	nstep = 1;
	vol = c->c_min;

	for (nstep = 0; nstep < c->c_step1cnt && vol < min; nstep++) {
		++reg_val;
		vol += c->c_step1;
	}

	if (c->c_step2start)
		vol = c->c_step2start;

	for (nstep = 0; nstep < c->c_step2cnt && vol < min; nstep++) {
		++reg_val;
		vol += c->c_step2;
	}

	if (vol > max)
		return EINVAL;

	iic_acquire_bus(tag, flags);
	if ((error = axppmic_read(tag, addr, c->c_voltage_reg, &val, flags)) == 0) {
		val &= ~c->c_voltage_mask;
		val |= __SHIFTIN(reg_val, c->c_voltage_mask);
		error = axppmic_write(tag, addr, c->c_voltage_reg, val, flags);
	}
	iic_release_bus(tag, flags);

	return error;
}

static int
axppmic_get_voltage(i2c_tag_t tag, i2c_addr_t addr, const struct axppmic_ctrl *c, u_int *pvol)
{
	const int flags = (cold ? I2C_F_POLL : 0);
	int reg_val, error;
	uint8_t val;

	if (!c->c_voltage_mask)
		return EINVAL;

	iic_acquire_bus(tag, flags);
	error = axppmic_read(tag, addr, c->c_voltage_reg, &val, flags);
	iic_release_bus(tag, flags);
	if (error)
		return error;

	reg_val = __SHIFTOUT(val, c->c_voltage_mask);
	if (reg_val < c->c_step1cnt) {
		*pvol = c->c_min + reg_val * c->c_step1;
	} else if (c->c_step2start) {
		*pvol = c->c_step2start +
		    ((reg_val - c->c_step1cnt) * c->c_step2);
	} else {
		*pvol = c->c_min + (c->c_step1cnt * c->c_step1) +
		    ((reg_val - c->c_step1cnt) * c->c_step2);
	}

	return 0;
}

static void
axppmic_power_poweroff(device_t dev)
{
	struct axppmic_softc *sc = device_private(dev);

	delay(1000000);

	iic_acquire_bus(sc->sc_i2c, I2C_F_POLL);
	axppmic_write(sc->sc_i2c, sc->sc_addr, AXP_POWER_DISABLE_REG, AXP_POWER_DISABLE_CTRL, I2C_F_POLL);
	iic_release_bus(sc->sc_i2c, I2C_F_POLL);
}

static struct fdtbus_power_controller_func axppmic_power_funcs = {
	.poweroff = axppmic_power_poweroff,
};

static void
axppmic_task_shut(void *priv)
{
	struct axppmic_softc *sc = priv;

	sysmon_pswitch_event(&sc->sc_smpsw, PSWITCH_EVENT_PRESSED);
}

static void
axppmic_sensor_update(struct sysmon_envsys *sme, envsys_data_t *e)
{
	struct axppmic_softc *sc = sme->sme_cookie;
	const struct axppmic_config *c = sc->sc_conf;
	const int flags = I2C_F_POLL;
	uint8_t val, lo, hi;

	e->state = ENVSYS_SINVALID;

	const bool battery_present =
	    sc->sc_sensor[AXP_SENSOR_BATT_PRESENT].state == ENVSYS_SVALID &&
	    sc->sc_sensor[AXP_SENSOR_BATT_PRESENT].value_cur == 1;

	switch (e->private) {
	case AXP_SENSOR_ACIN_PRESENT:
		if (axppmic_read(sc->sc_i2c, sc->sc_addr, AXP_POWER_SOURCE_REG, &val, flags) == 0) {
			e->state = ENVSYS_SVALID;
			e->value_cur = !!(val & AXP_POWER_SOURCE_ACIN_PRESENT);
		}
		break;
	case AXP_SENSOR_VBUS_PRESENT:
		if (axppmic_read(sc->sc_i2c, sc->sc_addr, AXP_POWER_SOURCE_REG, &val, flags) == 0) {
			e->state = ENVSYS_SVALID;
			e->value_cur = !!(val & AXP_POWER_SOURCE_VBUS_PRESENT);
		}
		break;
	case AXP_SENSOR_BATT_PRESENT:
		if (axppmic_read(sc->sc_i2c, sc->sc_addr, AXP_POWER_MODE_REG, &val, flags) == 0) {
			if (val & AXP_POWER_MODE_BATT_VALID) {
				e->state = ENVSYS_SVALID;
				e->value_cur = !!(val & AXP_POWER_MODE_BATT_PRESENT);
			}
		}
		break;
	case AXP_SENSOR_BATT_CHARGING:
		if (axppmic_read(sc->sc_i2c, sc->sc_addr, AXP_POWER_MODE_REG, &val, flags) == 0) {
			e->state = ENVSYS_SVALID;
			e->value_cur = !!(val & AXP_POWER_MODE_BATT_CHARGING);
		}
		break;
	case AXP_SENSOR_BATT_CHARGE_STATE:
		if (battery_present &&
		    axppmic_read(sc->sc_i2c, sc->sc_addr, AXP_BATT_CAP_REG, &val, flags) == 0 &&
		    (val & AXP_BATT_CAP_VALID) != 0) {
			const u_int batt_val = __SHIFTOUT(val, AXP_BATT_CAP_PERCENT);
			if (batt_val <= sc->sc_shut_thres) {
				e->state = ENVSYS_SCRITICAL;
				e->value_cur = ENVSYS_BATTERY_CAPACITY_CRITICAL;
			} else if (batt_val <= sc->sc_warn_thres) {
				e->state = ENVSYS_SWARNUNDER;
				e->value_cur = ENVSYS_BATTERY_CAPACITY_WARNING;
			} else {
				e->state = ENVSYS_SVALID;
				e->value_cur = ENVSYS_BATTERY_CAPACITY_NORMAL;
			}
		}
		break;
	case AXP_SENSOR_BATT_CAPACITY_PERCENT:
		if (battery_present &&
		    axppmic_read(sc->sc_i2c, sc->sc_addr, AXP_BATT_CAP_REG, &val, flags) == 0 &&
		    (val & AXP_BATT_CAP_VALID) != 0) {
			e->state = ENVSYS_SVALID;
			e->value_cur = __SHIFTOUT(val, AXP_BATT_CAP_PERCENT);
		}
		break;
	case AXP_SENSOR_BATT_VOLTAGE:
		if (battery_present &&
		    axppmic_read(sc->sc_i2c, sc->sc_addr, AXP_BATSENSE_HI_REG, &hi, flags) == 0 &&
		    axppmic_read(sc->sc_i2c, sc->sc_addr, AXP_BATSENSE_LO_REG, &lo, flags) == 0) {
			e->state = ENVSYS_SVALID;
			e->value_cur = AXP_ADC_RAW(hi, lo) * c->batsense_step;
		}
		break;
	case AXP_SENSOR_BATT_CHARGE_CURRENT:
		if (battery_present &&
		    axppmic_read(sc->sc_i2c, sc->sc_addr, AXP_POWER_SOURCE_REG, &val, flags) == 0 &&
		    (val & AXP_POWER_SOURCE_CHARGE_DIRECTION) != 0 &&
		    axppmic_read(sc->sc_i2c, sc->sc_addr, AXP_BATTCHG_HI_REG, &hi, flags) == 0 &&
		    axppmic_read(sc->sc_i2c, sc->sc_addr, AXP_BATTCHG_LO_REG, &lo, flags) == 0) {
			e->state = ENVSYS_SVALID;
			e->value_cur = AXP_ADC_RAW(hi, lo) * c->charge_step;
		}
		break;
	case AXP_SENSOR_BATT_DISCHARGE_CURRENT:
		if (battery_present &&
		    axppmic_read(sc->sc_i2c, sc->sc_addr, AXP_POWER_SOURCE_REG, &val, flags) == 0 &&
		    (val & AXP_POWER_SOURCE_CHARGE_DIRECTION) == 0 &&
		    axppmic_read(sc->sc_i2c, sc->sc_addr, AXP_BATTDISCHG_HI_REG, &hi, flags) == 0 &&
		    axppmic_read(sc->sc_i2c, sc->sc_addr, AXP_BATTDISCHG_LO_REG, &lo, flags) == 0) {
			e->state = ENVSYS_SVALID;
			e->value_cur = AXP_ADC_RAW(hi, lo) * c->discharge_step;
		}
		break;
	case AXP_SENSOR_BATT_MAXIMUM_CAPACITY:
		if (battery_present &&
		    axppmic_read(sc->sc_i2c, sc->sc_addr, AXP_BATT_MAX_CAP_HI_REG, &hi, flags) == 0 &&
		    axppmic_read(sc->sc_i2c, sc->sc_addr, AXP_BATT_MAX_CAP_LO_REG, &lo, flags) == 0) {
			e->state = (hi & AXP_BATT_MAX_CAP_VALID) ? ENVSYS_SVALID : ENVSYS_SINVALID;
			e->value_cur = AXP_COULOMB_RAW(hi, lo) * c->maxcap_step;
		}
		break;
	case AXP_SENSOR_BATT_CURRENT_CAPACITY:
		if (battery_present &&
		    axppmic_read(sc->sc_i2c, sc->sc_addr, AXP_BATT_COULOMB_HI_REG, &hi, flags) == 0 &&
		    axppmic_read(sc->sc_i2c, sc->sc_addr, AXP_BATT_COULOMB_LO_REG, &lo, flags) == 0) {
			e->state = (hi & AXP_BATT_COULOMB_VALID) ? ENVSYS_SVALID : ENVSYS_SINVALID;
			e->value_cur = AXP_COULOMB_RAW(hi, lo) * c->coulomb_step;
		}
		break;
	}
}

static void
axppmic_sensor_refresh(struct sysmon_envsys *sme, envsys_data_t *e)
{
	struct axppmic_softc *sc = sme->sme_cookie;
	const int flags = I2C_F_POLL;

	switch (e->private) {
	case AXP_SENSOR_BATT_CAPACITY_PERCENT:
	case AXP_SENSOR_BATT_VOLTAGE:
	case AXP_SENSOR_BATT_CHARGE_CURRENT:
	case AXP_SENSOR_BATT_DISCHARGE_CURRENT:
		/* Always update battery capacity and ADCs */
		iic_acquire_bus(sc->sc_i2c, flags);
		axppmic_sensor_update(sme, e);
		iic_release_bus(sc->sc_i2c, flags);
		break;
	default:
		/* Refresh if the sensor is not in valid state */
		if (e->state != ENVSYS_SVALID) {
			iic_acquire_bus(sc->sc_i2c, flags);
			axppmic_sensor_update(sme, e);
			iic_release_bus(sc->sc_i2c, flags);
		}
		break;
	}
}

static int
axppmic_intr(void *priv)
{
	struct axppmic_softc *sc = priv;
	const struct axppmic_config *c = sc->sc_conf;
	const int flags = I2C_F_POLL;
	uint8_t stat;
	u_int n;

	iic_acquire_bus(sc->sc_i2c, flags);
	for (n = 1; n <= c->irq_regs; n++) {
		if (axppmic_read(sc->sc_i2c, sc->sc_addr, AXP_IRQ_STATUS_REG(n), &stat, flags) == 0) {
			if (n == c->poklirq.reg && (stat & c->poklirq.mask) != 0)
				sysmon_task_queue_sched(0, axppmic_task_shut, sc);
			if (n == c->acinirq.reg && (stat & c->acinirq.mask) != 0)
				axppmic_sensor_update(sc->sc_sme, &sc->sc_sensor[AXP_SENSOR_ACIN_PRESENT]);
			if (n == c->vbusirq.reg && (stat & c->vbusirq.mask) != 0)
				axppmic_sensor_update(sc->sc_sme, &sc->sc_sensor[AXP_SENSOR_VBUS_PRESENT]);
			if (n == c->battirq.reg && (stat & c->battirq.mask) != 0)
				axppmic_sensor_update(sc->sc_sme, &sc->sc_sensor[AXP_SENSOR_BATT_PRESENT]);
			if (n == c->chargeirq.reg && (stat & c->chargeirq.mask) != 0)
				axppmic_sensor_update(sc->sc_sme, &sc->sc_sensor[AXP_SENSOR_BATT_CHARGING]);
			if (n == c->chargestirq.reg && (stat & c->chargestirq.mask) != 0)
				axppmic_sensor_update(sc->sc_sme, &sc->sc_sensor[AXP_SENSOR_BATT_CHARGE_STATE]);

			if (stat != 0)
				axppmic_write(sc->sc_i2c, sc->sc_addr,
				    AXP_IRQ_STATUS_REG(n), stat, flags);
		}
	}
	iic_release_bus(sc->sc_i2c, flags);

	return 1;
}

static void
axppmic_attach_acadapter(struct axppmic_softc *sc)
{
	envsys_data_t *e;

	e = &sc->sc_sensor[AXP_SENSOR_ACIN_PRESENT];
	e->private = AXP_SENSOR_ACIN_PRESENT;
	e->units = ENVSYS_INDICATOR;
	e->state = ENVSYS_SINVALID;
	strlcpy(e->desc, "ACIN present", sizeof(e->desc));
	sysmon_envsys_sensor_attach(sc->sc_sme, e);

	e = &sc->sc_sensor[AXP_SENSOR_VBUS_PRESENT];
	e->private = AXP_SENSOR_VBUS_PRESENT;
	e->units = ENVSYS_INDICATOR;
	e->state = ENVSYS_SINVALID;
	strlcpy(e->desc, "VBUS present", sizeof(e->desc));
	sysmon_envsys_sensor_attach(sc->sc_sme, e);
}

static void
axppmic_attach_battery(struct axppmic_softc *sc)
{
	const struct axppmic_config *c = sc->sc_conf;
	envsys_data_t *e;
	uint8_t val;

	iic_acquire_bus(sc->sc_i2c, I2C_F_POLL);
	if (axppmic_read(sc->sc_i2c, sc->sc_addr, AXP_BATT_CAP_WARN_REG, &val, I2C_F_POLL) == 0) {
		sc->sc_warn_thres = __SHIFTOUT(val, AXP_BATT_CAP_WARN_LV1) + 5;
		sc->sc_shut_thres = __SHIFTOUT(val, AXP_BATT_CAP_WARN_LV2);
	}
	iic_release_bus(sc->sc_i2c, I2C_F_POLL);

	e = &sc->sc_sensor[AXP_SENSOR_BATT_PRESENT];
	e->private = AXP_SENSOR_BATT_PRESENT;
	e->units = ENVSYS_INDICATOR;
	e->state = ENVSYS_SINVALID;
	strlcpy(e->desc, "battery present", sizeof(e->desc));
	sysmon_envsys_sensor_attach(sc->sc_sme, e);

	e = &sc->sc_sensor[AXP_SENSOR_BATT_CHARGING];
	e->private = AXP_SENSOR_BATT_CHARGING;
	e->units = ENVSYS_BATTERY_CHARGE;
	e->state = ENVSYS_SINVALID;
	strlcpy(e->desc, "charging", sizeof(e->desc));
	sysmon_envsys_sensor_attach(sc->sc_sme, e);

	e = &sc->sc_sensor[AXP_SENSOR_BATT_CHARGE_STATE];
	e->private = AXP_SENSOR_BATT_CHARGE_STATE;
	e->units = ENVSYS_BATTERY_CAPACITY;
	e->flags = ENVSYS_FMONSTCHANGED;
	e->state = ENVSYS_SINVALID;
	e->value_cur = ENVSYS_BATTERY_CAPACITY_NORMAL;
	strlcpy(e->desc, "charge state", sizeof(e->desc));
	sysmon_envsys_sensor_attach(sc->sc_sme, e);

	if (c->batsense_step) {
		e = &sc->sc_sensor[AXP_SENSOR_BATT_VOLTAGE];
		e->private = AXP_SENSOR_BATT_VOLTAGE;
		e->units = ENVSYS_SVOLTS_DC;
		e->state = ENVSYS_SINVALID;
		strlcpy(e->desc, "battery voltage", sizeof(e->desc));
		sysmon_envsys_sensor_attach(sc->sc_sme, e);
	}

	if (c->charge_step) {
		e = &sc->sc_sensor[AXP_SENSOR_BATT_CHARGE_CURRENT];
		e->private = AXP_SENSOR_BATT_CHARGE_CURRENT;
		e->units = ENVSYS_SAMPS;
		e->state = ENVSYS_SINVALID;
		strlcpy(e->desc, "battery charge current", sizeof(e->desc));
		sysmon_envsys_sensor_attach(sc->sc_sme, e);
	}

	if (c->discharge_step) {
		e = &sc->sc_sensor[AXP_SENSOR_BATT_DISCHARGE_CURRENT];
		e->private = AXP_SENSOR_BATT_DISCHARGE_CURRENT;
		e->units = ENVSYS_SAMPS;
		e->state = ENVSYS_SINVALID;
		strlcpy(e->desc, "battery discharge current", sizeof(e->desc));
		sysmon_envsys_sensor_attach(sc->sc_sme, e);
	}

	if (c->has_fuel_gauge) {
		e = &sc->sc_sensor[AXP_SENSOR_BATT_CAPACITY_PERCENT];
		e->private = AXP_SENSOR_BATT_CAPACITY_PERCENT;
		e->units = ENVSYS_INTEGER;
		e->state = ENVSYS_SINVALID;
		e->flags = ENVSYS_FPERCENT;
		strlcpy(e->desc, "battery percent", sizeof(e->desc));
		sysmon_envsys_sensor_attach(sc->sc_sme, e);
	}

	if (c->maxcap_step) {
		e = &sc->sc_sensor[AXP_SENSOR_BATT_MAXIMUM_CAPACITY];
		e->private = AXP_SENSOR_BATT_MAXIMUM_CAPACITY;
		e->units = ENVSYS_SAMPHOUR;
		e->state = ENVSYS_SINVALID;
		strlcpy(e->desc, "battery maximum capacity", sizeof(e->desc));
		sysmon_envsys_sensor_attach(sc->sc_sme, e);
	}

	if (c->coulomb_step) {
		e = &sc->sc_sensor[AXP_SENSOR_BATT_CURRENT_CAPACITY];
		e->private = AXP_SENSOR_BATT_CURRENT_CAPACITY;
		e->units = ENVSYS_SAMPHOUR;
		e->state = ENVSYS_SINVALID;
		strlcpy(e->desc, "battery current capacity", sizeof(e->desc));
		sysmon_envsys_sensor_attach(sc->sc_sme, e);
	}
}

static void
axppmic_attach_sensors(struct axppmic_softc *sc)
{
	if (sc->sc_conf->has_battery) {
		sc->sc_sme = sysmon_envsys_create();
		sc->sc_sme->sme_name = device_xname(sc->sc_dev);
		sc->sc_sme->sme_cookie = sc;
		sc->sc_sme->sme_refresh = axppmic_sensor_refresh;
		sc->sc_sme->sme_class = SME_CLASS_BATTERY;
		sc->sc_sme->sme_flags = SME_INIT_REFRESH;

		axppmic_attach_acadapter(sc);
		axppmic_attach_battery(sc);

		sysmon_envsys_register(sc->sc_sme);
	}
}


static int
axppmic_match(device_t parent, cfdata_t match, void *aux)
{
	struct i2c_attach_args *ia = aux;
	int match_result;

	if (iic_use_direct_match(ia, match, compat_data, &match_result))
		return match_result;

	/* This device is direct-config only. */

	return 0;
}

static void
axppmic_attach(device_t parent, device_t self, void *aux)
{
	struct axppmic_softc *sc = device_private(self);
	const struct device_compatible_entry *dce = NULL;
	const struct axppmic_config *c;
	struct axpreg_attach_args aaa;
	struct i2c_attach_args *ia = aux;
	int phandle, child, i;
	uint8_t irq_mask, val;
	int error;
	void *ih;

	(void) iic_compatible_match(ia, compat_data, &dce);
	KASSERT(dce != NULL);
	c = (void *)dce->data;

	sc->sc_dev = self;
	sc->sc_i2c = ia->ia_tag;
	sc->sc_addr = ia->ia_addr;
	sc->sc_phandle = ia->ia_cookie;
	sc->sc_conf = c;

	aprint_naive("\n");
	aprint_normal(": %s\n", c->name);

	if (c->has_mode_set) {
		const bool master_mode = of_hasprop(sc->sc_phandle, "x-powers,self-working-mode") ||
		    of_hasprop(sc->sc_phandle, "x-powers,master-mode");

		iic_acquire_bus(sc->sc_i2c, I2C_F_POLL);
		axppmic_write(sc->sc_i2c, sc->sc_addr, AXP_ADDR_EXT_REG,
		    master_mode ? AXP_ADDR_EXT_MASTER : AXP_ADDR_EXT_SLAVE, I2C_F_POLL);
		iic_release_bus(sc->sc_i2c, I2C_F_POLL);
	}

	iic_acquire_bus(sc->sc_i2c, I2C_F_POLL);
	error = axppmic_read(sc->sc_i2c, sc->sc_addr, AXP_CHIP_ID_REG, &val, I2C_F_POLL);
	iic_release_bus(sc->sc_i2c, I2C_F_POLL);
	if (error != 0) {
		aprint_error_dev(self, "couldn't read chipid\n");
		return;
	}
	aprint_debug_dev(self, "chipid %#x\n", val);

	sc->sc_smpsw.smpsw_name = device_xname(self);
	sc->sc_smpsw.smpsw_type = PSWITCH_TYPE_POWER;
	sysmon_pswitch_register(&sc->sc_smpsw);

	if (c->irq_regs > 0) {
		iic_acquire_bus(sc->sc_i2c, I2C_F_POLL);
		for (i = 1; i <= c->irq_regs; i++) {
			irq_mask = 0;
			if (i == c->poklirq.reg)
				irq_mask |= c->poklirq.mask;
			if (i == c->acinirq.reg)
				irq_mask |= c->acinirq.mask;
			if (i == c->vbusirq.reg)
				irq_mask |= c->vbusirq.mask;
			if (i == c->battirq.reg)
				irq_mask |= c->battirq.mask;
			if (i == c->chargeirq.reg)
				irq_mask |= c->chargeirq.mask;
			if (i == c->chargestirq.reg)
				irq_mask |= c->chargestirq.mask;
			axppmic_write(sc->sc_i2c, sc->sc_addr, AXP_IRQ_ENABLE_REG(i), irq_mask, I2C_F_POLL);
		}
		iic_release_bus(sc->sc_i2c, I2C_F_POLL);

		ih = fdtbus_intr_establish(sc->sc_phandle, 0, IPL_VM, FDT_INTR_MPSAFE,
		    axppmic_intr, sc);
		if (ih == NULL) {
			aprint_error_dev(self, "WARNING: couldn't establish interrupt handler\n");
		}
	}

	fdtbus_register_power_controller(sc->sc_dev, sc->sc_phandle,
	    &axppmic_power_funcs);

	phandle = of_find_firstchild_byname(sc->sc_phandle, "regulators");
	if (phandle > 0) {
		aaa.reg_i2c = sc->sc_i2c;
		aaa.reg_addr = sc->sc_addr;
		for (i = 0; i < c->ncontrols; i++) {
			const struct axppmic_ctrl *ctrl = &c->controls[i];
			child = of_find_firstchild_byname(phandle, ctrl->c_name);
			if (child <= 0)
				continue;
			aaa.reg_ctrl = ctrl;
			aaa.reg_phandle = child;
			config_found(sc->sc_dev, &aaa, NULL);
		}
	}

	/* Notify pinctrl drivers that regulators are available. */
	fdtbus_pinctrl_configure();

	if (c->has_battery)
		axppmic_attach_sensors(sc);
}

static int
axpreg_acquire(device_t dev)
{
	return 0;
}

static void
axpreg_release(device_t dev)
{
}

static int
axpreg_enable(device_t dev, bool enable)
{
	struct axpreg_softc *sc = device_private(dev);
	const struct axppmic_ctrl *c = sc->sc_ctrl;
	const int flags = (cold ? I2C_F_POLL : 0);
	uint8_t val;
	int error;

	if (!c->c_enable_mask)
		return EINVAL;

	iic_acquire_bus(sc->sc_i2c, flags);
	if ((error = axppmic_read(sc->sc_i2c, sc->sc_addr, c->c_enable_reg, &val, flags)) == 0) {
		val &= ~c->c_enable_mask;
		if (enable)
			val |= c->c_enable_val;
		else
			val |= c->c_disable_val;
		error = axppmic_write(sc->sc_i2c, sc->sc_addr, c->c_enable_reg, val, flags);
	}
	iic_release_bus(sc->sc_i2c, flags);

	return error;
}

static int
axpreg_set_voltage(device_t dev, u_int min_uvol, u_int max_uvol)
{
	struct axpreg_softc *sc = device_private(dev);
	const struct axppmic_ctrl *c = sc->sc_ctrl;

	return axppmic_set_voltage(sc->sc_i2c, sc->sc_addr, c,
	    min_uvol / 1000, max_uvol / 1000);
}

static int
axpreg_get_voltage(device_t dev, u_int *puvol)
{
	struct axpreg_softc *sc = device_private(dev);
	const struct axppmic_ctrl *c = sc->sc_ctrl;
	int error;
	u_int vol;

	error = axppmic_get_voltage(sc->sc_i2c, sc->sc_addr, c, &vol);
	if (error)
		return error;

	*puvol = vol * 1000;
	return 0;
}

static struct fdtbus_regulator_controller_func axpreg_funcs = {
	.acquire = axpreg_acquire,
	.release = axpreg_release,
	.enable = axpreg_enable,
	.set_voltage = axpreg_set_voltage,
	.get_voltage = axpreg_get_voltage,
};

static int
axpreg_match(device_t parent, cfdata_t match, void *aux)
{
	return 1;
}

static void
axpreg_attach(device_t parent, device_t self, void *aux)
{
	struct axpreg_softc *sc = device_private(self);
	struct axpreg_attach_args *aaa = aux;
	const int phandle = aaa->reg_phandle;
	const char *name;
	u_int uvol, min_uvol, max_uvol;

	sc->sc_dev = self;
	sc->sc_i2c = aaa->reg_i2c;
	sc->sc_addr = aaa->reg_addr;
	sc->sc_ctrl = aaa->reg_ctrl;

	fdtbus_register_regulator_controller(self, phandle,
	    &axpreg_funcs);

	aprint_naive("\n");
	name = fdtbus_get_string(phandle, "regulator-name");
	if (name)
		aprint_normal(": %s\n", name);
	else
		aprint_normal("\n");

	axpreg_get_voltage(self, &uvol);
	if (of_getprop_uint32(phandle, "regulator-min-microvolt", &min_uvol) == 0 &&
	    of_getprop_uint32(phandle, "regulator-max-microvolt", &max_uvol) == 0) {
		if (uvol < min_uvol || uvol > max_uvol) {
			aprint_debug_dev(self, "fix voltage %u uV -> %u/%u uV\n",
			    uvol, min_uvol, max_uvol);
			axpreg_set_voltage(self, min_uvol, max_uvol);
		}
	}

	if (of_hasprop(phandle, "regulator-always-on") ||
	    of_hasprop(phandle, "regulator-boot-on")) {
		axpreg_enable(self, true);
	}
}

CFATTACH_DECL_NEW(axppmic, sizeof(struct axppmic_softc),
    axppmic_match, axppmic_attach, NULL, NULL);

CFATTACH_DECL_NEW(axpreg, sizeof(struct axpreg_softc),
    axpreg_match, axpreg_attach, NULL, NULL);
