// Copyright (c) 2018 The Particl Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <usbdevice/usbwrapper.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <logging.h>

namespace usb_device {

static libusb_context *usb_context = NULL;

int webusb_init()
{
    if (!usb_context) {
        /* Init Libusb */
        if (libusb_init(&usb_context)) {
            return -1;
        }
#ifdef WIN32
        //libusb_set_option(usb_context, LIBUSB_OPTION_USE_USBDK);
#endif
    }

    return 0;
}

int webusb_exit()
{
    if (usb_context) {
        libusb_exit(usb_context);
        usb_context = NULL;
    }

    return 0;
}

static webusb_device *new_webusb_device(void)
{
    webusb_device *dev = (webusb_device*) calloc(1, sizeof(webusb_device));
    return dev;
}

static void free_webusb_device(webusb_device *dev)
{
    /* Free the device itself */
    free(dev);
}

static char *make_path(libusb_device *dev, int interface_number)
{
    char str[64];
    snprintf(str, sizeof(str), "%04x:%04x:%02x",
        libusb_get_bus_number(dev),
        libusb_get_device_address(dev),
        interface_number);
    str[sizeof(str)-1] = '\0';

    return strdup(str);
}

webusb_device *webusb_open_path(const char *path)
{
    webusb_device *dev = NULL;

    libusb_device **devs;
    libusb_device *usb_dev;
    int res;
    int d = 0;
    int good_open = 0;

    if (webusb_init() < 0) {
        return NULL;
    }

    dev = new_webusb_device();

    libusb_get_device_list(usb_context, &devs);
    while ((usb_dev = devs[d++]) != NULL) {
        struct libusb_device_descriptor desc;
        struct libusb_config_descriptor *conf_desc = NULL;
        int i,j,k;
        libusb_get_device_descriptor(usb_dev, &desc);

        if (desc.bDeviceClass != 0x00) {
            continue;
        }

        if (libusb_get_active_config_descriptor(usb_dev, &conf_desc) < 0)
            continue;
        for (j = 0; j < conf_desc->bNumInterfaces; j++) {
            const struct libusb_interface *intf = &conf_desc->interface[j];
            for (k = 0; k < intf->num_altsetting; k++) {
                const struct libusb_interface_descriptor *intf_desc;
                intf_desc = &intf->altsetting[k];

                if (intf_desc->bInterfaceClass == LIBUSB_CLASS_VENDOR_SPEC && desc.idVendor == 0x1209 && desc.idProduct == 0x53c1) {
                    char *dev_path = make_path(usb_dev, intf_desc->bInterfaceNumber);

                    if (!strcmp(dev_path, path)) {
                        /* Matched Paths. Open this device */

                        /* OPEN HERE */
                        res = libusb_open(usb_dev, &dev->device_handle);
                        if (res < 0) {
                            LogPrintf("%s: Can't open device: %d\n", __func__, res);
                            free(dev_path);
                            break;
                        }

                        // libusb will automatically detach the kernel driver on an interface when claiming the interface,
                        // and attach it when releasing the interface.
                        res = libusb_set_auto_detach_kernel_driver(dev->device_handle, 1);

                        good_open = 1;
                        res = libusb_claim_interface(dev->device_handle, intf_desc->bInterfaceNumber);
                        if (res < 0) {
                            LogPrintf("%s: Can't claim interface %d: %d\n", __func__, intf_desc->bInterfaceNumber, res);
                            free(dev_path);
                            libusb_close(dev->device_handle);
                            good_open = 0;
                            break;
                        }

                        /* Store off the string descriptor indexes */
                        dev->manufacturer_index = desc.iManufacturer;
                        dev->product_index      = desc.iProduct;
                        dev->serial_index       = desc.iSerialNumber;

                        /* Store off the interface number */
                        dev->interface = intf_desc->bInterfaceNumber;

                        /* Find the INPUT and OUTPUT endpoints. An
                           OUTPUT endpoint is not required. */
                        for (i = 0; i < intf_desc->bNumEndpoints; i++) {
                            const struct libusb_endpoint_descriptor *ep
                                = &intf_desc->endpoint[i];

                            /* Determine the type and direction of this
                               endpoint. */
                            int is_interrupt =
                                (ep->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK)
                                  == LIBUSB_TRANSFER_TYPE_INTERRUPT;
                            int is_output =
                                (ep->bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK)
                                  == LIBUSB_ENDPOINT_OUT;
                            int is_input =
                                (ep->bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK)
                                  == LIBUSB_ENDPOINT_IN;

                            /* Decide whether to use it for input or output. */
                            if (dev->input_endpoint == 0 &&
                                is_interrupt && is_input) {
                                /* Use this endpoint for INPUT */
                                dev->input_endpoint = ep->bEndpointAddress;
                                dev->input_ep_max_packet_size = ep->wMaxPacketSize;
                            }
                            if (dev->output_endpoint == 0 &&
                                is_interrupt && is_output) {
                                /* Use this endpoint for OUTPUT */
                                dev->output_endpoint = ep->bEndpointAddress;
                            }
                        }
                    }
                    free(dev_path);
                }
            }
        }
        libusb_free_config_descriptor(conf_desc);
    }

    libusb_free_device_list(devs, 1);

    /* If we have a good handle, return it. */
    if (good_open) {
        return dev;
    }

    /* Unable to open any devices. */
    free_webusb_device(dev);
    return NULL;
}

void webusb_close(webusb_device *dev)
{
    if (!dev) {
        return;
    }

    int rv = libusb_release_interface(dev->device_handle, dev->interface);
    if (rv) {
        LogPrintf("%s: Release interface failed with %d.\n", __func__, rv);
    }

    libusb_close(dev->device_handle);

    free_webusb_device(dev);
}

/* Get the first language the device says it reports. This comes from
   USB string #0. */
static uint16_t get_first_language(libusb_device_handle *dev)
{
    uint16_t buf[32];
    int len;

    /* Get the string from libusb. */
    len = libusb_get_string_descriptor(dev,
            0x0, /* String ID */
            0x0, /* Language */
            (unsigned char*)buf,
            sizeof(buf));

    if (len < 4) {
        return 0x0;
    }

    return buf[1]; /* First two bytes are len and descriptor type. */
}
/* This function returns a newly allocated wide string containing the USB
   device string numbered by the index. The returned string must be freed
   by using free(). */
static wchar_t *get_usb_string(libusb_device_handle *dev, uint8_t idx)
{
    char buf[512];
    int len;
    wchar_t *str = NULL;

    /* Determine which language to use. */
    uint16_t lang;
    //lang = get_usb_code_for_current_locale();
    //if (!is_language_supported(dev, lang))
    lang = get_first_language(dev);

    /* Get the string from libusb. */
    len = libusb_get_string_descriptor(dev,
            idx,
            lang,
            (unsigned char*)buf,
            sizeof(buf));

    if (len < 0) {
        return NULL;
    }

    /* The following code will only work for
       code points that can be represented as a single UTF-16 character,
       and will incorrectly convert any code points which require more
       than one UTF-16 character.

       Skip over the first character (2-bytes).  */
    len -= 2;
    str = (wchar_t*) malloc((len / 2 + 1) * sizeof(wchar_t));
    int i;
    for (i = 0; i < len / 2; i++) {
        str[i] = buf[i * 2 + 2] | (buf[i * 2 + 3] << 8);
    }
    str[len / 2] = '\0';

    return str;
}

struct webusb_device_info *webusb_enumerate(unsigned short vendor_id, unsigned short product_id)
{
    libusb_device **devs;
    libusb_device *dev;
    libusb_device_handle *handle;
    ssize_t num_devs;
    int i = 0;

    struct webusb_device_info *root = NULL; /* return object */
    struct webusb_device_info *cur_dev = NULL;

    num_devs = libusb_get_device_list(usb_context, &devs);
    if (num_devs < 0) {
        return NULL;
    }
    while ((dev = devs[i++]) != NULL) {
        struct libusb_device_descriptor desc;
        struct libusb_config_descriptor *conf_desc = NULL;
        int j, k;
        int interface_num = 0;

        int res = libusb_get_device_descriptor(dev, &desc);
        unsigned short dev_vid = desc.idVendor;
        unsigned short dev_pid = desc.idProduct;

        if (desc.bDeviceClass != 0x00) {
            continue;
        }

        res = libusb_get_active_config_descriptor(dev, &conf_desc);
        if (res < 0) {
            res = libusb_get_config_descriptor(dev, 0, &conf_desc);
        }

        if (conf_desc) {
            for (j = 0; j < conf_desc->bNumInterfaces; j++) {
                const struct libusb_interface *intf = &conf_desc->interface[j];
                for (k = 0; k < intf->num_altsetting; k++) {
                    const struct libusb_interface_descriptor *intf_desc;
                    intf_desc = &intf->altsetting[k];

                    // TODO: search webusbDeviceTypes
                    if (intf_desc->bInterfaceClass == LIBUSB_CLASS_VENDOR_SPEC && dev_vid == 0x1209 && dev_pid == 0x53c1) {
                        interface_num = intf_desc->bInterfaceNumber;

                        struct webusb_device_info *tmp;

                        tmp = (struct webusb_device_info*) calloc(1, sizeof(struct webusb_device_info));
                        if (cur_dev) {
                            cur_dev->next = tmp;
                        }
                        else {
                            root = tmp;
                        }
                        cur_dev = tmp;

                        /* Fill out the record */
                        cur_dev->next = NULL;
                        cur_dev->path = make_path(dev, interface_num);

                        res = libusb_open(dev, &handle);

                        if (res >= 0) {
                            /* Serial Number */
                            if (desc.iSerialNumber > 0)
                                cur_dev->serial_number =
                                    get_usb_string(handle, desc.iSerialNumber);

                            /* Manufacturer and Product strings */
                            if (desc.iManufacturer > 0)
                                cur_dev->manufacturer_string =
                                    get_usb_string(handle, desc.iManufacturer);

                            if (desc.iProduct > 0)
                                cur_dev->product_string =
                                    get_usb_string(handle, desc.iProduct);

                            libusb_close(handle);
                        }
                        /* VID/PID */
                        cur_dev->vendor_id = dev_vid;
                        cur_dev->product_id = dev_pid;

                        /* Release Number */
                        cur_dev->release_number = desc.bcdDevice;

                        /* Interface Number */
                        cur_dev->interface_number = interface_num;
                    }
                } /* altsettings */
            } /* interfaces */
            libusb_free_config_descriptor(conf_desc);
        }
    }

    libusb_free_device_list(devs, 1);

    return root;
}

void webusb_free_enumeration(struct webusb_device_info *devs)
{
    struct webusb_device_info *d = devs;
    while (d) {
        struct webusb_device_info *next = d->next;
        free(d->path);
        if (d->serial_number) {free(d->serial_number);}
        if (d->manufacturer_string) {free(d->manufacturer_string);}
        if (d->product_string) {free(d->product_string);}
        free(d);
        d = next;
    }
}

int webusb_write(webusb_device *dev, const unsigned char *data, size_t length)
{
    if (dev->output_endpoint <= 0) {
        return -1;
    }

    int transferred, res = libusb_interrupt_transfer(dev->device_handle,
        dev->output_endpoint,
        (unsigned char*)data,
        length,
        &transferred,
        5000);

    if (res) {
        LogPrintf("%s: Transfer failed with %d.\n", __func__, res);
        return -1;
    }

    if (transferred < (int) length) {
        LogPrintf("%s: Under write %d / %d.\n", __func__, transferred, length);
        return -1;
    }

    return transferred;
};

int webusb_read_timeout(webusb_device *dev, unsigned char *data, size_t length, int milliseconds)
{
    if (dev->input_endpoint <= 0) {
        return -1;
    }

    int transferred, res = libusb_interrupt_transfer(dev->device_handle,
        dev->input_endpoint,
        data,
        length,
        &transferred,
        milliseconds);

    if (res) {
        LogPrintf("%s: Transfer failed with %d.\n", __func__, res);
        return -1;
    }

    if (transferred < (int) length) {
        LogPrintf("%s: Under read %d / %d.\n", __func__, transferred, length);
        return -1;
    }

    return transferred;
};

} // usb_device
