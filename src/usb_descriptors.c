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
#include "tusb.h"

#define _PID_MAP(itf, n)  ( (CFG_TUD_##itf) << (n) )

#define USB_VID 0x1209
#define USB_PID 0xf1de

/*
 * HID U2F report descriptor
 */
#define TUD_HID_REPORT_DESC_U2F_INOUT() \
    0x06, 0xD0, 0xF1, /* Usage Page (FIDO Alliance), FIDO_USAGE_PAGE */  \
    0x09, 0x01,       /* Usage (U2F HID Auth. Device) FIDO_USAGE_U2FHID */ \
    0xA1, 0x01,       /* Collection (Application), HID_APPLICATION */ \
    0x09, 0x20,       /*  Usage (Input Report Data), FIDO_USAGE_DATA_IN */ \
    0x15, 0x00,       /*  Logical Minimum (0) */ \
    0x26, 0xFF, 0x00, /*  Logical Maximum (255) */ \
    0x75, 0x08,       /*  Report Size (8) */ \
    0x95, 0x40,       /*  Report Count (64), HID_INPUT_REPORT_BYTES */ \
    0x81, 0x02,       /*  Input (Data, Var, Abs), Usage */ \
    0x09, 0x21,       /*  Usage (Output Report Data), FIDO_USAGE_DATA_OUT */ \
    0x15, 0x00,       /*  Logical Minimum (0) */ \
    0x26, 0xFF, 0x00, /*  Logical Maximum (255) */ \
    0x75, 0x08,       /*  Report Size (8) */ \
    0x95, 0x40,       /*  Report Count (64), HID_OUTPUT_REPORT_BYTES */ \
    0x91, 0x02,       /*  Output (Data, Var, Abs), Usage */ \
    0xC0              /* End Collection */

#define REPORT_DESCRIPTOR_LEN 34
/* U2F Hid report descriptor constant structure */
static const uint8_t desc_hid_report[] =
{
  TUD_HID_REPORT_DESC_U2F_INOUT()
};

/* Callback for GET_HID_REPORT_DESCRIPTOR */
const uint8_t *tud_hid_descriptor_report_cb(uint8_t itf)
{
  (void) itf;
  return desc_hid_report;
}

/*
 * USB Device descriptor
 */
static const tusb_desc_device_t desc_device =
{
    .bLength            = sizeof(tusb_desc_device_t),
    .bDescriptorType    = TUSB_DESC_DEVICE,
    .bcdUSB             = 0x0200,
    .bDeviceClass       = 0x00,
    .bDeviceSubClass    = 0x00,
    .bDeviceProtocol    = 0x00,
    .bMaxPacketSize0    = CFG_TUD_ENDPOINT0_SIZE,

    .idVendor           = USB_VID,
    .idProduct          = USB_PID,
    .bcdDevice          = 0x0100,

    .iManufacturer      = 0x01,
    .iProduct           = 0x02,
    .iSerialNumber      = 0x03,

    .bNumConfigurations = 0x01
};

/* callback for GET_DEVICE_DESCRIPTOR  */
const uint8_t *tud_descriptor_device_cb(void)
{
  return (const uint8_t *) &desc_device;
}

/* Configuration descriptor
 * one configuration possible (HID)
 */
enum
{
  ITF_NUM_HID,
  ITF_NUM_TOTAL
};

#define  USB_CONFIG_TOTAL_LEN  (TUD_CONFIG_DESC_LEN + TUD_HID_INOUT_DESC_LEN)

#define EPNUM_HID   0x01


static const uint8_t desc_configuration[] =
{
  /* Config number, interface count, string index, total length, attribute,
   * power in mA
   */
  TUD_CONFIG_DESCRIPTOR(1, ITF_NUM_TOTAL, 0, USB_CONFIG_TOTAL_LEN, 0x00, 100),
  /* Interface number, string index, protocol, report descriptor len,
   * EP In & Out address, size & polling interval
   */
  TUD_HID_INOUT_DESCRIPTOR(ITF_NUM_HID, 0, HID_ITF_PROTOCOL_NONE,
          sizeof(desc_hid_report), EPNUM_HID, 0x80 | EPNUM_HID,
          CFG_TUD_HID_EP_BUFSIZE, 5)
};

/* Callback for GET_CONFIGURATION_DESCRIPTOR */
const uint8_t * tud_descriptor_configuration_cb(uint8_t index)
{
  (void) index; // for multiple configurations
  return desc_configuration;
}


/*
 * String descriptors
 */
static const char *string_desc_arr [] =
{
  (const char[]) { 0x09, 0x04 },    /* 0: Supported Language: English (0x0409) */
  "Danielinux",                     /* 1: Manufacturer                         */
  "U2F-Fido rp2040",                /* 2: Product                              */
  "122023",                         /* 3: Serial number, MMYYYY                */
};

static uint16_t _desc_str[32];

/* Callback for GET_STRING_DESCRIPTOR */
const uint16_t * tud_descriptor_string_cb(uint8_t index, uint16_t langid)
{
  (void) langid;

  uint8_t chr_count;

  if ( index == 0)
  {
    memcpy(&_desc_str[1], string_desc_arr[0], 2);
    chr_count = 1;
  }else
  {
    // Note: the 0xEE index string is a Microsoft OS 1.0 Descriptors.
    // https://docs.microsoft.com/en-us/windows-hardware/drivers/usbcon/microsoft-defined-usb-descriptors

    if ( !(index < sizeof(string_desc_arr)/sizeof(string_desc_arr[0])) ) return NULL;

    const char* str = string_desc_arr[index];

    // Cap at max char
    chr_count = (uint8_t)strlen(str);
    if ( chr_count > 31 ) chr_count = 31;

    // Convert ASCII string into UTF-16
    for(uint8_t i=0; i<chr_count; i++)
    {
      _desc_str[1+i] = str[i];
    }
  }

  // first byte is length (including header), second byte is string type
  _desc_str[0] = (uint16_t)((TUSB_DESC_STRING << 8U ) | (2U*chr_count + 2U));

  return _desc_str;
}
