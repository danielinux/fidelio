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

#include <stdint.h>
#include "indicator.h"
#include "pins.h"
#include "pico/stdlib.h"
#include "hardware/gpio.h"

#ifdef RGB_LED
#include "hardware/clocks.h"
#include "hardware/pio.h"

#define WS2812_T1 2
#define WS2812_T2 5
#define WS2812_T3 3
#define WS2812_WRAP_TARGET 0
#define WS2812_WRAP 3

static uint16_t ws2812_program_instructions[4];

static struct pio_program ws2812_program = {
    .instructions = ws2812_program_instructions,
    .length = 4,
    .origin = -1,
};

static inline pio_sm_config ws2812_program_get_default_config(uint offset)
{
    pio_sm_config c = pio_get_default_sm_config();
    sm_config_set_sideset(&c, 1, false, false);
    sm_config_set_wrap(&c, offset + WS2812_WRAP_TARGET, offset + WS2812_WRAP);
    sm_config_set_out_shift(&c, false, true, 24);
    sm_config_set_fifo_join(&c, PIO_FIFO_JOIN_TX);
    return c;
}

static void ws2812_program_init(PIO pio, uint sm, uint offset, uint pin, float freq)
{
    pio_gpio_init(pio, pin);
    pio_sm_set_consecutive_pindirs(pio, sm, pin, 1, true);
    pio_sm_config c = ws2812_program_get_default_config(offset);
    sm_config_set_sideset_pins(&c, pin);
    sm_config_set_clkdiv(&c, clock_get_hz(clk_sys) / (freq * (WS2812_T1 + WS2812_T2 + WS2812_T3)));
    pio_sm_init(pio, sm, offset, &c);
    pio_sm_set_enabled(pio, sm, true);
}

static PIO rgb_pio = pio0;
static uint rgb_sm = 0;
static uint rgb_offset = 0;

static inline uint32_t rgb_pack(uint8_t r, uint8_t g, uint8_t b)
{
    return ((uint32_t)g << 16) | ((uint32_t)r << 8) | b;
}

static inline void rgb_write(uint8_t r, uint8_t g, uint8_t b)
{
    pio_sm_put_blocking(rgb_pio, rgb_sm, rgb_pack(r, g, b) << 8u);
}

#endif

void indicator_init(void)
{
#ifdef RGB_LED
    ws2812_program_instructions[0] = (uint16_t)(pio_encode_out(pio_x, 1) |
                                                pio_encode_sideset(1, 0) |
                                                pio_encode_delay(WS2812_T3 - 1));
    ws2812_program_instructions[1] = (uint16_t)(pio_encode_jmp_not_x(WS2812_WRAP) |
                                                pio_encode_sideset(1, 1) |
                                                pio_encode_delay(WS2812_T1 - 1));
    ws2812_program_instructions[2] = (uint16_t)(pio_encode_jmp(WS2812_WRAP_TARGET) |
                                                pio_encode_sideset(1, 1) |
                                                pio_encode_delay(WS2812_T2 - 1));
    ws2812_program_instructions[3] = (uint16_t)(pio_encode_nop() |
                                                pio_encode_sideset(1, 0) |
                                                pio_encode_delay(WS2812_T2 - 1));

    rgb_offset = pio_add_program(rgb_pio, &ws2812_program);
    ws2812_program_init(rgb_pio, rgb_sm, rgb_offset, RGB_LED, 800000.0f);
    rgb_write(0, 0, 0);
#else
    gpio_init(PRESENCE_LED);
    gpio_set_dir(PRESENCE_LED, GPIO_OUT);
    gpio_put(PRESENCE_LED, 0);
#endif
}

void indicator_set_idle(void)
{
    indicator_set(0, 0, 0);
}

void indicator_set(uint16_t r, uint16_t g, uint16_t b)
{
#ifdef RGB_LED
    rgb_write((uint8_t)r, (uint8_t)g, (uint8_t)b);
#else
    gpio_put(PRESENCE_LED, (r || g || b) ? 1 : 0);
#endif
}

void indicator_wait_for_button(uint16_t r, uint16_t g, uint16_t b)
{
#ifdef RGB_LED
    unsigned int idx = 0;
    absolute_time_t next_step = make_timeout_time_ms(80);
    gpio_init(PRESENCE_BUTTON);
    gpio_set_dir(PRESENCE_BUTTON, GPIO_IN);
    gpio_pull_up(PRESENCE_BUTTON);
    asm volatile("dmb");

    /* If already pressed, wait for release before arming */
    indicator_set(r, g, b);
    while (gpio_get(PRESENCE_BUTTON) == 0) {
        sleep_ms(2);
    }

    next_step = make_timeout_time_ms(80);
    while (gpio_get(PRESENCE_BUTTON) != 0) {
        sleep_ms(2);
    }
    sleep_ms(30); /* Debounce */
    indicator_set_idle();
#else
    indicator_set(r, g, b);
    /* If already pressed, wait for release before arming */
    while (gpio_get(PRESENCE_BUTTON) == 0) {
        sleep_ms(2);
    }
    while (gpio_get(PRESENCE_BUTTON) != 0) {
        sleep_ms(2);
    }
    sleep_ms(30);
    indicator_set_idle();
#endif
}
