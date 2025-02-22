/* $NetBSD: rk_gmac.c,v 1.12 2019/05/05 19:10:05 jmcneill Exp $ */

/*-
 * Copyright (c) 2018 Jared McNeill <jmcneill@invisible.ca>
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

__KERNEL_RCSID(0, "$NetBSD: rk_gmac.c,v 1.12 2019/05/05 19:10:05 jmcneill Exp $");

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/device.h>
#include <sys/intr.h>
#include <sys/systm.h>
#include <sys/gpio.h>

#include <net/if.h>
#include <net/if_ether.h>
#include <net/if_media.h>

#include <dev/mii/miivar.h>

#include <dev/ic/dwc_gmac_var.h>
#include <dev/ic/dwc_gmac_reg.h>

#include <dev/fdt/fdtvar.h>
#include <dev/fdt/syscon.h>

#define	RK_GMAC_TXDLY_DEFAULT	0x30
#define	RK_GMAC_RXDLY_DEFAULT	0x10

enum rk_gmac_type {
	GMAC_RK3328 = 1,
	GMAC_RK3399
};

static const struct of_compat_data compat_data[] = {
	{ "rockchip,rk3328-gmac",	GMAC_RK3328 },
	{ "rockchip,rk3399-gmac",	GMAC_RK3399 },
	{ NULL }
};

struct rk_gmac_softc {
	struct dwc_gmac_softc	sc_base;
	struct syscon		*sc_syscon;
	enum rk_gmac_type	sc_type;
};

/*
 * RK3328 specific
 */

#define	RK3328_GRF_MAC_CON0	0x0900
#define	 RK3328_GRF_MAC_CON0_RXDLY	__BITS(13,7)
#define	 RK3328_GRF_MAC_CON0_TXDLY	__BITS(6,0)

#define	RK3328_GRF_MAC_CON1	0x0904
#define	 RK3328_GRF_MAC_CON1_CLKSEL	__BITS(12,11)
#define	  RK3328_GRF_MAC_CON1_CLKSEL_125M	0
#define	  RK3328_GRF_MAC_CON1_CLKSEL_2_5M	2
#define	  RK3328_GRF_MAC_CON1_CLKSEL_25M	3
#define	 RK3328_GRF_MAC_CON1_MODE	__BIT(9)
#define	 RK3328_GRF_MAC_CON1_SEL	__BITS(6,4)
#define	  RK3328_GRF_MAC_CON1_SEL_RGMII	1
#define	 RK3328_GRF_MAC_CON1_RXDLY_EN	__BIT(1)
#define	 RK3328_GRF_MAC_CON1_TXDLY_EN	__BIT(0)

static void
rk3328_gmac_set_mode_rgmii(struct dwc_gmac_softc *sc, u_int tx_delay, u_int rx_delay)
{
	struct rk_gmac_softc * const rk_sc = (struct rk_gmac_softc *)sc;
	uint32_t write_mask, write_val;

	syscon_lock(rk_sc->sc_syscon);

	write_mask = (RK3328_GRF_MAC_CON1_MODE | RK3328_GRF_MAC_CON1_SEL) << 16;
	write_val = __SHIFTIN(RK3328_GRF_MAC_CON1_SEL_RGMII, RK3328_GRF_MAC_CON1_SEL);
	syscon_write_4(rk_sc->sc_syscon, RK3328_GRF_MAC_CON1, write_mask | write_val);

#if notyet
	write_mask = (RK3328_GRF_MAC_CON0_TXDLY | RK3328_GRF_MAC_CON0_RXDLY) << 16;
	write_val = __SHIFTIN(tx_delay, RK3328_GRF_MAC_CON0_TXDLY) |
		    __SHIFTIN(rx_delay, RK3328_GRF_MAC_CON0_RXDLY);
	syscon_write_4(rk_sc->sc_syscon, RK3328_GRF_MAC_CON0, write_mask | write_val);

	write_mask = (RK3328_GRF_MAC_CON1_RXDLY_EN | RK3328_GRF_MAC_CON1_TXDLY_EN) << 16;
	write_val = RK3328_GRF_MAC_CON1_RXDLY_EN | RK3328_GRF_MAC_CON1_TXDLY_EN;
	syscon_write_4(rk_sc->sc_syscon, RK3328_GRF_MAC_CON1, write_mask | write_val);
#endif

	syscon_unlock(rk_sc->sc_syscon);
}

static void
rk3328_gmac_set_speed_rgmii(struct dwc_gmac_softc *sc, int speed)
{
	struct rk_gmac_softc * const rk_sc = (struct rk_gmac_softc *)sc;
#if 0
	u_int clksel;

	switch (speed) {
	case IFM_10_T:
		clksel = RK3328_GRF_MAC_CON1_CLKSEL_2_5M;
		break;
	case IFM_100_TX:
		clksel = RK3328_GRF_MAC_CON1_CLKSEL_25M;
		break;
	default:
		clksel = RK3328_GRF_MAC_CON1_CLKSEL_125M;
		break;
	}
#endif

	syscon_lock(rk_sc->sc_syscon);
	syscon_write_4(rk_sc->sc_syscon, RK3328_GRF_MAC_CON1,
	    (RK3328_GRF_MAC_CON1_CLKSEL << 16) |
	    __SHIFTIN(RK3328_GRF_MAC_CON1_CLKSEL_125M, RK3328_GRF_MAC_CON1_CLKSEL));
	syscon_unlock(rk_sc->sc_syscon);
}

/*
 * RK3399 specific
 */

#define	RK3399_GRF_SOC_CON5		0x0c214
#define	 RK3399_GRF_SOC_CON5_GMAC_PHY_INTF_SEL	__BITS(11,9)
#define	 RK3399_GRF_SOC_CON5_GMAC_FLOWCTRL	__BIT(8)
#define	 RK3399_GRF_SOC_CON5_GMAC_SPEED		__BIT(7)
#define	 RK3399_GRF_SOC_CON5_RMII_MODE		__BIT(6)
#define	 RK3399_GRF_SOC_CON5_GMAC_CLK_SEL	__BITS(5,4)
#define	  RK3399_GRF_SOC_CON5_GMAC_CLK_SEL_125M	0
#define	  RK3399_GRF_SOC_CON5_GMAC_CLK_SEL_25M	3
#define	  RK3399_GRF_SOC_CON5_GMAC_CLK_SEL_2_5M	2
#define	 RK3399_GRF_SOC_CON5_RMII_CLK_SEL	__BIT(3)
#define	RK3399_GRF_SOC_CON6		0x0c218
#define	 RK3399_GRF_SOC_CON6_GMAC_RXCLK_DLY_ENA	__BIT(15)
#define	 RK3399_GRF_SOC_CON6_GMAC_CLK_RX_DL_CFG	__BITS(14,8)
#define	 RK3399_GRF_SOC_CON6_GMAC_TXCLK_DLY_ENA	__BIT(7)
#define	 RK3399_GRF_SOC_CON6_GMAC_CLK_TX_DL_CFG	__BITS(6,0)

static void
rk3399_gmac_set_mode_rgmii(struct dwc_gmac_softc *sc, u_int tx_delay, u_int rx_delay)
{
	struct rk_gmac_softc * const rk_sc = (struct rk_gmac_softc *)sc;

	const uint32_t con5_mask =
	    (RK3399_GRF_SOC_CON5_RMII_MODE | RK3399_GRF_SOC_CON5_GMAC_PHY_INTF_SEL) << 16;
	const uint32_t con5 = __SHIFTIN(1, RK3399_GRF_SOC_CON5_GMAC_PHY_INTF_SEL);

#if notyet
	const uint32_t con6_mask =
	    (RK3399_GRF_SOC_CON6_GMAC_RXCLK_DLY_ENA |
		RK3399_GRF_SOC_CON6_GMAC_TXCLK_DLY_ENA |
		RK3399_GRF_SOC_CON6_GMAC_CLK_RX_DL_CFG |
		RK3399_GRF_SOC_CON6_GMAC_CLK_TX_DL_CFG) << 16;
	const uint32_t con6 =
	    (tx_delay ? RK3399_GRF_SOC_CON6_GMAC_TXCLK_DLY_ENA : 0) |
	    (rx_delay ? RK3399_GRF_SOC_CON6_GMAC_RXCLK_DLY_ENA : 0) |
	    __SHIFTIN(rx_delay, RK3399_GRF_SOC_CON6_GMAC_CLK_RX_DL_CFG) |
	    __SHIFTIN(tx_delay, RK3399_GRF_SOC_CON6_GMAC_CLK_TX_DL_CFG);
#endif

	syscon_lock(rk_sc->sc_syscon);
	syscon_write_4(rk_sc->sc_syscon, RK3399_GRF_SOC_CON5, con5 | con5_mask);
#if notyet
	syscon_write_4(rk_sc->sc_syscon, RK3399_GRF_SOC_CON6, con6 | con6_mask);
#endif
	syscon_unlock(rk_sc->sc_syscon);
}

static void
rk3399_gmac_set_speed_rgmii(struct dwc_gmac_softc *sc, int speed)
{
	struct rk_gmac_softc * const rk_sc = (struct rk_gmac_softc *)sc;
	u_int clksel;

	switch (speed) {
	case IFM_10_T:
		clksel = RK3399_GRF_SOC_CON5_GMAC_CLK_SEL_2_5M;
		break;
	case IFM_100_TX:
		clksel = RK3399_GRF_SOC_CON5_GMAC_CLK_SEL_25M;
		break;
	default:
		clksel = RK3399_GRF_SOC_CON5_GMAC_CLK_SEL_125M;
		break;
	}

	const uint32_t con5_mask =
	    RK3399_GRF_SOC_CON5_GMAC_CLK_SEL << 16;
	const uint32_t con5 =
	    __SHIFTIN(clksel, RK3399_GRF_SOC_CON5_GMAC_CLK_SEL);

	syscon_lock(rk_sc->sc_syscon);
	syscon_write_4(rk_sc->sc_syscon, RK3399_GRF_SOC_CON5, con5 | con5_mask);
	syscon_unlock(rk_sc->sc_syscon);
}

static int
rk_gmac_reset(const int phandle)
{
	struct fdtbus_gpio_pin *pin_reset;
	const u_int *reset_delay_us;
	bool reset_active_low;
	int len;

	if (!of_hasprop(phandle, "snps,reset-gpio"))
		return 0;

	pin_reset = fdtbus_gpio_acquire(phandle, "snps,reset-gpio", GPIO_PIN_OUTPUT);
	if (pin_reset == NULL)
		return ENOENT;

	reset_delay_us = fdtbus_get_prop(phandle, "snps,reset-delays-us", &len);
	if (reset_delay_us == NULL || len != 12)
		return ENXIO;

	reset_active_low = of_hasprop(phandle, "snps,reset-active-low");

	fdtbus_gpio_write_raw(pin_reset, reset_active_low ? 1 : 0);
	delay(be32toh(reset_delay_us[0]));
	fdtbus_gpio_write_raw(pin_reset, reset_active_low ? 0 : 1);
	delay(be32toh(reset_delay_us[1]));
	fdtbus_gpio_write_raw(pin_reset, reset_active_low ? 1 : 0);
	delay(be32toh(reset_delay_us[2]));

	return 0;
}

static int
rk_gmac_intr(void *arg)
{
	return dwc_gmac_intr(arg);
}

static int
rk_gmac_setup_clocks(int phandle)
{
	static const char * const clknames[] = {
#if 0
		"stmmaceth",
		"mac_clk_rx", 
		"mac_clk_tx",
		"clk_mac_ref",
		"clk_mac_refout",
		"aclk_mac",
		"pclk_mac"
#else
		"stmmaceth",
		"aclk_mac",
		"pclk_mac",
		"mac_clk_tx",
		"mac_clk_rx"
#endif
	};
	static const char * const rstnames[] = {
		"stmmaceth"
	};
	struct fdtbus_reset *rst;
	struct clk *clk;
	int error, n;

	fdtbus_clock_assign(phandle);

	for (n = 0; n < __arraycount(clknames); n++) {
		clk = fdtbus_clock_get(phandle, clknames[n]);
		if (clk == NULL) {
			aprint_error(": couldn't get %s clock\n", clknames[n]);
			return ENXIO;
		}
		error = clk_enable(clk);
		if (error != 0) {
			aprint_error(": couldn't enable %s clock: %d\n",
			    clknames[n], error);
			return error;
		}
	}

	for (n = 0; n < __arraycount(rstnames); n++) {
		rst = fdtbus_reset_get(phandle, rstnames[n]);
		if (rst == NULL) {
			aprint_error(": couldn't get %s reset\n", rstnames[n]);
			return ENXIO;
		}
		error = fdtbus_reset_deassert(rst);
		if (error != 0) {
			aprint_error(": couldn't de-assert %s reset: %d\n",
			    rstnames[n], error);
			return error;
		}
	}

	delay(5000);

	return 0;
}

static int
rk_gmac_match(device_t parent, cfdata_t cf, void *aux)
{
	struct fdt_attach_args * const faa = aux;

	return of_match_compat_data(faa->faa_phandle, compat_data);
}

static void
rk_gmac_attach(device_t parent, device_t self, void *aux)
{
	struct rk_gmac_softc * const rk_sc = device_private(self);
	struct dwc_gmac_softc * const sc = &rk_sc->sc_base;
	struct fdt_attach_args * const faa = aux;
	const int phandle = faa->faa_phandle;
	const char *phy_mode;
	char intrstr[128];
	bus_addr_t addr;
	bus_size_t size;
	u_int tx_delay, rx_delay;

	if (fdtbus_get_reg(phandle, 0, &addr, &size) != 0) {
		aprint_error(": couldn't get registers\n");
		return;
	}

	rk_sc->sc_type = of_search_compatible(phandle, compat_data)->data;

	rk_sc->sc_syscon = fdtbus_syscon_acquire(phandle, "rockchip,grf");
	if (rk_sc->sc_syscon == NULL) {
		aprint_error(": couldn't get grf syscon\n");
		return;
	}

	if (of_getprop_uint32(phandle, "tx_delay", &tx_delay) != 0)
		tx_delay = RK_GMAC_TXDLY_DEFAULT;

	if (of_getprop_uint32(phandle, "rx_delay", &rx_delay) != 0)
		rx_delay = RK_GMAC_RXDLY_DEFAULT;

	sc->sc_dev = self;
	sc->sc_bst = faa->faa_bst;
	if (bus_space_map(sc->sc_bst, addr, size, 0, &sc->sc_bsh) != 0) {
		aprint_error(": couldn't map registers\n");
		return;
	}
	sc->sc_dmat = faa->faa_dmat;

	if (!fdtbus_intr_str(phandle, 0, intrstr, sizeof(intrstr))) {
		aprint_error(": failed to decode interrupt\n");
		return;
	}

	if (rk_gmac_setup_clocks(phandle) != 0)
		return;

	if (rk_gmac_reset(phandle) != 0)
		aprint_error_dev(self, "PHY reset failed\n");

	/* Rock64 seems to need more time for the reset to complete */
	delay(100000);

#if notyet
	if (of_hasprop(phandle, "snps,force_thresh_dma_mode"))
		sc->sc_flags |= DWC_GMAC_FORCE_THRESH_DMA_MODE;
#endif

	phy_mode = fdtbus_get_string(phandle, "phy-mode");
	if (phy_mode == NULL) {
		aprint_error(": missing 'phy-mode' property\n");
		return;
	}

	switch (rk_sc->sc_type) {
	case GMAC_RK3328:
		if (strcmp(phy_mode, "rgmii") == 0) {
			rk3328_gmac_set_mode_rgmii(sc, tx_delay, rx_delay);

			sc->sc_set_speed = rk3328_gmac_set_speed_rgmii;
		} else {
			aprint_error(": unsupported phy-mode '%s'\n", phy_mode);
			return;
		}
		break;
	case GMAC_RK3399:
		if (strcmp(phy_mode, "rgmii") == 0) {
			rk3399_gmac_set_mode_rgmii(sc, tx_delay, rx_delay);

			sc->sc_set_speed = rk3399_gmac_set_speed_rgmii;
		} else {
			aprint_error(": unsupported phy-mode '%s'\n", phy_mode);
			return;
		}
		break;
	}

	aprint_naive("\n");
	aprint_normal(": GMAC\n");

	if (dwc_gmac_attach(sc, MII_PHY_ANY, GMAC_MII_CLK_150_250M_DIV102) != 0)
		return;

	if (fdtbus_intr_establish(phandle, 0, IPL_NET, 0, rk_gmac_intr, sc) == NULL) {
		aprint_error_dev(self, "failed to establish interrupt on %s\n", intrstr);
		return;
	}
	aprint_normal_dev(self, "interrupting on %s\n", intrstr);
}

CFATTACH_DECL_NEW(rk_gmac, sizeof(struct rk_gmac_softc),
	rk_gmac_match, rk_gmac_attach, NULL, NULL);
