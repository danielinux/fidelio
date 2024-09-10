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

#include "pico/stdlib.h"
#include "hardware/gpio.h"
#include "pins.h"

#ifdef USE_BOOTSEL_BUTTON
#include "hardware/sync.h"
#include "hardware/structs/ioqspi.h"
#include "hardware/structs/sio.h"

bool get_bootsel_button_state(void);


/* Code to check if the bootsel button is pressed
 *
 * Blatantly pinched from lib/tinyusb/hw/bsp/rp2040/family.c
 */ 
bool __no_inline_not_in_flash_func(_get_bootsel_button)(void) {
  const uint CS_PIN_INDEX = 1;

  /* Must disable interrupts, as interrupt handlers may be in flash, and we
   * are about to temporarily disable flash access!
   */
  uint32_t flags = save_and_disable_interrupts();

  /* Set chip select to Hi-Z */
  hw_write_masked(&ioqspi_hw->io[CS_PIN_INDEX].ctrl,
                  GPIO_OVERRIDE_LOW << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
                  IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);

  /* Note we can't call into any sleep functions in flash right now */
  for (volatile int i = 0; i < 1000; ++i);

  /* The HI GPIO registers in SIO can observe and control the 6 QSPI pins.
   * Note the button pulls the pin *low* when pressed.
   */
  bool button_state = (sio_hw->gpio_hi_in & (1u << CS_PIN_INDEX));

  /* Need to restore the state of chip select, else we are going to have a
   * bad time when we return to code in flash!
   */
  hw_write_masked(&ioqspi_hw->io[CS_PIN_INDEX].ctrl,
                  GPIO_OVERRIDE_NORMAL << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
                  IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);

  restore_interrupts(flags);

  return button_state;
}

bool get_bootsel_button_state(void) {
    return !_get_bootsel_button();
}

#endif

bool get_presence(void) {
#ifdef USE_BOOTSEL_BUTTON
    return get_bootsel_button_state();
#else
    if (gpio_get(PRESENCE_BUTTON) == PRESENCE_PRESSED) {
        return true;
    } else {
        return false;
    }
#endif
}
