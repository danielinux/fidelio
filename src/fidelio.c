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
#include <stdbool.h>
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
#include "fdo.h"
#include "indicator.h"
    
extern void u2f_init(void);
extern void u2f_factory_reset(void);

#define FACTORY_RESET_HOLD_US (10 * 1000 * 1000)

static void presence_button_init(void)
{
    gpio_init(PRESENCE_BUTTON);
    gpio_set_dir(PRESENCE_BUTTON, GPIO_IN);
    gpio_pull_up(PRESENCE_BUTTON);
}

static bool presence_button_pressed(void)
{
    return gpio_get(PRESENCE_BUTTON) == 0;
}

static void factory_reset_startup_check(void)
{
    if (!presence_button_pressed())
        return;

    /* Button held at power-on: arm factory reset before other subsystems start */
    indicator_init();
    indicator_set(0x20, 0x20, 0); /* Yellow while counting */

    absolute_time_t pressed_since = get_absolute_time();
    while (presence_button_pressed()) {
        if (absolute_time_diff_us(pressed_since, get_absolute_time()) >= FACTORY_RESET_HOLD_US) {
            u2f_factory_reset();
        }
        tight_loop_contents();
    }
    indicator_set_idle();
}

void system_boot(void)
{
    /* Setting system clock */
    set_sys_clock_48mhz();
    
    /* Setting GPIOs for Button first, so we can gate startup on long-press */
    presence_button_init();
    factory_reset_startup_check();

    /* Setting GPIOs for Led + Button */
    indicator_init();

    /* Initializing U2F parser */
    u2f_init();
    fdo_init();

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
