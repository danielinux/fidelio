/* Fidelio
 *
 * (c) 2023 Daniele Lacamera <root@danielinux.net>
 *
 *
 * Fidelio is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Fidelio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 *
 */
#include <stdio.h>
#include <stdint.h>
#include "pico/stdlib.h"
#include "pico/multicore.h"
#include "hardware/gpio.h"
#include "hardware/adc.h"
#include "bsp/board.h"
#include "pins.h"
#include "tusb.h"
#include "usb_descriptors.h"
#include "user_settings.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "hardware/clocks.h"
#include "led.h" 
    
extern void u2f_init(void);

void system_boot(void)
{
	int rc;
	
    /* Setting system clock */
    set_sys_clock_48mhz();
    
    /* Setting GPIOs for Led + Button */
    rc = u2f_led_init();
    hard_assert(rc == PICO_OK);

	/* If using BOOTSEL don't set the PRESENCE_BUTTON */
	#ifndef USE_PRESENCE_BUTTON
    gpio_init(PRESENCE_BUTTON);
    gpio_set_dir(PRESENCE_BUTTON, GPIO_IN);
    gpio_pull_up(PRESENCE_BUTTON);
	#endif
	
    /* Momentarily blink led on startup - functioning indicator */
    u2f_set_led(1);
    sleep_ms(250);
    u2f_set_led(0);

    /* Initializing U2F parser */
    u2f_init();

    /* Initializing TinyUSB device */
    tusb_init();
}

int main(void) {
    system_boot();

    /* Main loop: transfer control to USB */
    while (1) {
        tud_task();
    }
}

