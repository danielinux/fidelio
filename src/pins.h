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
#ifndef BUTTON_H
#define BUTTON_H

/* Board pinout.
 *
 * Exactly one FIDELIO_BOARD_* macro is defined by CMakeLists.txt from the
 * BOARD configuration variable. Each block below must define:
 *
 *   PRESENCE_BUTTON       GPIO of the normally-open button to GND
 *   PRESENCE_LED          GPIO of a plain LED, for boards that have one
 *   RGB_LED               GPIO of a WS2812 RGB LED, for boards that have one
 *                         (define exactly one of PRESENCE_LED / RGB_LED;
 *                          indicator.c switches on RGB_LED being defined)
 *   FIDELIO_ADC_CHANNELS  initialiser list of the ADC channels rand.c may
 *                         sample for entropy. Channel N is GPIO 26+N, so a
 *                         channel whose GPIO is used for anything else - most
 *                         notably the presence button - must be left out:
 *                         adc_gpio_init() would take the pin away from the
 *                         digital input.
 */

#if defined(FIDELIO_BOARD_PICO)

/* Raspberry Pi Pico (RP2040) */
#define PRESENCE_BUTTON 15
#define PRESENCE_LED PICO_DEFAULT_LED_PIN
/* Button is on GPIO15, so all four ADC inputs (GPIO26-29) are free. */
#define FIDELIO_ADC_CHANNELS { 0, 1, 2, 3 }

#elif defined(FIDELIO_BOARD_RP2040_ZERO)

/* Waveshare RP2040-Zero v1.1 */
#define PRESENCE_BUTTON 29
#define RGB_LED 16
/* Channel 3 is GPIO29, which this board uses for the presence button. */
#define FIDELIO_ADC_CHANNELS { 0, 1, 2 }

#else

#error "No board selected: define one of FIDELIO_BOARD_PICO, FIDELIO_BOARD_RP2040_ZERO. Configure with -DBOARD=pico or -DBOARD=rp2040-zero; see the 'Supported boards' section of the README."

#endif

/* ADC channel N samples GPIO 26+N. */
#define FIDELIO_ADC_CHANNEL_GPIO(ch) (26 + (ch))

#endif
