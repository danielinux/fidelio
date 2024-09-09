/* Fidelio
 *
 * (c) 2023 Peardox
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

#include "led.h"
/* Pico W devices use a GPIO on the WIFI chip for the LED,
 * so when building for Pico W, CYW43_WL_GPIO_LED_PIN will be defined
 */

#ifdef CYW43_WL_GPIO_LED_PIN
#include "pico/cyw43_arch.h"
#include "pico/cyw43_driver.h"
#include "hardware/clocks.h"
#endif

/* Perform initialization */
int u2f_led_init(void) {
#ifndef CYW43_WL_GPIO_LED_PIN
    /* A device like Pico that uses a GPIO for the LED will define U2F_LED
     * so we can use normal GPIO functionality to turn the led on and off  
	 */
    gpio_init(U2F_LED);
    gpio_set_dir(U2F_LED, GPIO_OUT);
    return PICO_OK;
#else
    /* For Pico W devices we need to initialize the driver etc */
    cyw43_set_pio_clock_divisor(1, 0);
    return cyw43_arch_init();
#endif
}

/* Turn the led on or off */
void u2f_set_led(bool led_on) {
#ifndef CYW43_WL_GPIO_LED_PIN
    /* Just set the GPIO on or off */
    gpio_put(U2F_LED, led_on);
#else
    /* Ask the wifi "driver" to set the GPIO on or off */
    cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, led_on);
#endif
}

