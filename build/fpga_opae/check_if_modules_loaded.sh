#!/bin/bash

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Intel Corporation

#Logic to check if module already loaded
if lsmod | grep regmap_mmio_mod &> /dev/null ; then
	echo "regmap-mmio-mod is loaded"
else
	modprobe regmap-mmio-mod
fi

if lsmod | grep intel_fpga_pci &> /dev/null ; then
        echo "intel-fpga-pci loaded"
else
        modprobe intel-fpga-pci
fi

if lsmod | grep ifpga_sec_mgr &> /dev/null ; then
        echo "ifpga-sec-mgr is loaded"
else
        modprobe ifpga-sec-mgr
fi

if lsmod | grep fpga_mgr_mod &> /dev/null ; then
        echo "fpga-mgr-mod is loaded"
else
        modprobe fpga-mgr-mod
fi

if lsmod | grep spi_bitbang_mod &> /dev/null ; then
        echo "spi-bitbang-mod is loaded"
else
        modprobe spi-bitbang-mod
fi

if lsmod | grep i2c_altera &> /dev/null ; then
        echo "i2c-altera is loaded"
else
        modprobe i2c-altera
fi

if lsmod | grep intel_fpga_fme &> /dev/null ; then
        echo "intel-fpga-fme is loaded"
else
        modprobe intel-fpga-fme 
fi

if lsmod | grep pac_n3000_net &> /dev/null ; then
        echo "pac_n3000_net is loaded"
else
        modprobe pac_n3000_net
fi

if lsmod | grep intel_max10 &> /dev/null ; then
        echo "intel-max10 is loaded"
else
        modprobe intel-max10
fi

if lsmod | grep intel_fpga_pac_iopll &> /dev/null ; then
        echo "intel-fpga-pac-iopll is loaded"
else
        modprobe intel-fpga-pac-iopll
fi

if lsmod | grep intel_fpga_afu &> /dev/null ; then
        echo "intel-fpga-afu is loaded"
else
        modprobe intel-fpga-afu
fi

if lsmod | grep intel_on_chip_flash &> /dev/null ; then
        echo "intel-on-chip-flash is loaded"
else
        modprobe intel-on-chip-flash
fi

if lsmod | grep c827_retimer &> /dev/null ; then
        echo "c827_retimer is loaded"
else
        modprobe c827_retimer
fi

if lsmod | grep avmmi_bmc &> /dev/null ; then
        echo "avmmi-bmc is loaded"
else
        modprobe avmmi-bmc
fi

if lsmod | grep intel_fpga_pac_hssi &> /dev/null ; then
        echo "intel-fpga-pac-hssi is loaded"
else
        modprobe intel-fpga-pac-hssi
fi

if lsmod | grep spi_altera_mod &> /dev/null ; then
        echo "spi-altera-mod is loaded"
else
        modprobe spi-altera-mod
fi

if lsmod | grep spi_nor_mod &> /dev/null ; then
        echo "spi-nor-mod is loaded"
else
        modprobe spi-nor-mod
fi

if lsmod | grep altera_asmip2 &> /dev/null ; then
        echo "altera-asmip2 is loaded"
else
        modprobe altera-asmip2
fi

if lsmod | grep intel_generic_qspi &> /dev/null ; then
        echo "intel-generic-qspi is loaded"
else
        modprobe intel-generic-qspi
fi
