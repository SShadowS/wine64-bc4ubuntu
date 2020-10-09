/*
 * Copyright 2016 Dmitry Timoshkov
 * Copyright 2020 Esme Povirk
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#if 0
#pragma makedep unix
#endif

#include "config.h"
#include "wine/port.h"

#include <stdarg.h>

#define NONAMELESSUNION

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "winbase.h"
#include "objbase.h"

#include "wincodecs_private.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(wincodecs);

#ifdef SONAME_LIBPNG

#include <png.h>

static void *libpng_handle;
#define MAKE_FUNCPTR(f) static typeof(f) * p##f
MAKE_FUNCPTR(png_create_info_struct);
MAKE_FUNCPTR(png_create_read_struct);
MAKE_FUNCPTR(png_destroy_read_struct);
MAKE_FUNCPTR(png_error);
MAKE_FUNCPTR(png_get_bit_depth);
MAKE_FUNCPTR(png_get_color_type);
MAKE_FUNCPTR(png_get_error_ptr);
MAKE_FUNCPTR(png_get_image_height);
MAKE_FUNCPTR(png_get_image_width);
MAKE_FUNCPTR(png_get_io_ptr);
MAKE_FUNCPTR(png_get_pHYs);
MAKE_FUNCPTR(png_get_PLTE);
MAKE_FUNCPTR(png_get_tRNS);
MAKE_FUNCPTR(png_read_info);
MAKE_FUNCPTR(png_set_bgr);
MAKE_FUNCPTR(png_set_crc_action);
MAKE_FUNCPTR(png_set_error_fn);
MAKE_FUNCPTR(png_set_gray_to_rgb);
MAKE_FUNCPTR(png_set_read_fn);
MAKE_FUNCPTR(png_set_swap);
MAKE_FUNCPTR(png_set_tRNS_to_alpha);
#undef MAKE_FUNCPTR

static CRITICAL_SECTION init_png_cs;
static CRITICAL_SECTION_DEBUG init_png_cs_debug =
{
    0, 0, &init_png_cs,
    { &init_png_cs_debug.ProcessLocksList,
      &init_png_cs_debug.ProcessLocksList },
    0, 0, { (DWORD_PTR)(__FILE__ ": init_png_cs") }
};
static CRITICAL_SECTION init_png_cs = { &init_png_cs_debug, -1, 0, 0, 0, 0 };

static void *load_libpng(void)
{
    void *result;

    RtlEnterCriticalSection(&init_png_cs);

    if(!libpng_handle && (libpng_handle = dlopen(SONAME_LIBPNG, RTLD_NOW)) != NULL) {

#define LOAD_FUNCPTR(f) \
    if((p##f = dlsym(libpng_handle, #f)) == NULL) { \
        libpng_handle = NULL; \
        RtlLeaveCriticalSection(&init_png_cs); \
        return NULL; \
    }
        LOAD_FUNCPTR(png_create_info_struct);
        LOAD_FUNCPTR(png_create_read_struct);
        LOAD_FUNCPTR(png_destroy_read_struct);
        LOAD_FUNCPTR(png_error);
        LOAD_FUNCPTR(png_get_bit_depth);
        LOAD_FUNCPTR(png_get_color_type);
        LOAD_FUNCPTR(png_get_error_ptr);
        LOAD_FUNCPTR(png_get_image_height);
        LOAD_FUNCPTR(png_get_image_width);
        LOAD_FUNCPTR(png_get_io_ptr);
        LOAD_FUNCPTR(png_get_pHYs);
        LOAD_FUNCPTR(png_get_PLTE);
        LOAD_FUNCPTR(png_get_tRNS);
        LOAD_FUNCPTR(png_read_info);
        LOAD_FUNCPTR(png_set_bgr);
        LOAD_FUNCPTR(png_set_crc_action);
        LOAD_FUNCPTR(png_set_error_fn);
        LOAD_FUNCPTR(png_set_gray_to_rgb);
        LOAD_FUNCPTR(png_set_read_fn);
        LOAD_FUNCPTR(png_set_swap);
        LOAD_FUNCPTR(png_set_tRNS_to_alpha);

#undef LOAD_FUNCPTR
    }

    result = libpng_handle;

    RtlLeaveCriticalSection(&init_png_cs);

    return result;
}

struct png_decoder
{
    struct decoder decoder;
    struct decoder_frame decoder_frame;
};

static inline struct png_decoder *impl_from_decoder(struct decoder* iface)
{
    return CONTAINING_RECORD(iface, struct png_decoder, decoder);
}

static void user_error_fn(png_structp png_ptr, png_const_charp error_message)
{
    jmp_buf *pjmpbuf;

    /* This uses setjmp/longjmp just like the default. We can't use the
     * default because there's no way to access the jmp buffer in the png_struct
     * that works in 1.2 and 1.4 and allows us to dynamically load libpng. */
    WARN("PNG error: %s\n", debugstr_a(error_message));
    pjmpbuf = ppng_get_error_ptr(png_ptr);
    longjmp(*pjmpbuf, 1);
}

static void user_warning_fn(png_structp png_ptr, png_const_charp warning_message)
{
    WARN("PNG warning: %s\n", debugstr_a(warning_message));
}

static void user_read_data(png_structp png_ptr, png_bytep data, png_size_t length)
{
    IStream *stream = ppng_get_io_ptr(png_ptr);
    HRESULT hr;
    ULONG bytesread;

    hr = stream_read(stream, data, length, &bytesread);
    if (FAILED(hr) || bytesread != length)
    {
        ppng_error(png_ptr, "failed reading data");
    }
}

HRESULT CDECL png_decoder_initialize(struct decoder *iface, IStream *stream, struct decoder_stat *st)
{
    struct png_decoder *This = impl_from_decoder(iface);
    png_structp png_ptr;
    png_infop info_ptr;
    png_infop end_info;
    jmp_buf jmpbuf;
    HRESULT hr = E_FAIL;
    int color_type, bit_depth;
    png_bytep trans;
    int num_trans;
    png_uint_32 transparency;
    png_color_16p trans_values;
    png_uint_32 ret, xres, yres;
    int unit_type;
    png_colorp png_palette;
    int num_palette;
    int i;

    png_ptr = ppng_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_ptr)
    {
        return E_FAIL;
    }

    info_ptr = ppng_create_info_struct(png_ptr);
    if (!info_ptr)
    {
        ppng_destroy_read_struct(&png_ptr, NULL, NULL);
        return E_FAIL;
    }

    end_info = ppng_create_info_struct(png_ptr);
    if (!end_info)
    {
        ppng_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        return E_FAIL;
    }

    /* set up setjmp/longjmp error handling */
    if (setjmp(jmpbuf))
    {
        hr = WINCODEC_ERR_UNKNOWNIMAGEFORMAT;
        goto end;
    }
    ppng_set_error_fn(png_ptr, jmpbuf, user_error_fn, user_warning_fn);
    ppng_set_crc_action(png_ptr, PNG_CRC_QUIET_USE, PNG_CRC_QUIET_USE);

    /* seek to the start of the stream */
    hr = stream_seek(stream, 0, STREAM_SEEK_SET, NULL);
    if (FAILED(hr))
    {
        goto end;
    }

    /* set up custom i/o handling */
    ppng_set_read_fn(png_ptr, stream, user_read_data);

    /* read the header */
    ppng_read_info(png_ptr, info_ptr);

    /* choose a pixel format */
    color_type = ppng_get_color_type(png_ptr, info_ptr);
    bit_depth = ppng_get_bit_depth(png_ptr, info_ptr);

    /* PNGs with bit-depth greater than 8 are network byte order. Windows does not expect this. */
    if (bit_depth > 8)
        ppng_set_swap(png_ptr);

    /* check for color-keyed alpha */
    transparency = ppng_get_tRNS(png_ptr, info_ptr, &trans, &num_trans, &trans_values);
    if (!transparency)
        num_trans = 0;

    if (transparency && (color_type == PNG_COLOR_TYPE_RGB ||
        (color_type == PNG_COLOR_TYPE_GRAY && bit_depth == 16)))
    {
        /* expand to RGBA */
        if (color_type == PNG_COLOR_TYPE_GRAY)
            ppng_set_gray_to_rgb(png_ptr);
        ppng_set_tRNS_to_alpha(png_ptr);
        color_type = PNG_COLOR_TYPE_RGB_ALPHA;
    }

    switch (color_type)
    {
    case PNG_COLOR_TYPE_GRAY_ALPHA:
        /* WIC does not support grayscale alpha formats so use RGBA */
        ppng_set_gray_to_rgb(png_ptr);
        /* fall through */
    case PNG_COLOR_TYPE_RGB_ALPHA:
        This->decoder_frame.bpp = bit_depth * 4;
        switch (bit_depth)
        {
        case 8:
            ppng_set_bgr(png_ptr);
            This->decoder_frame.pixel_format = GUID_WICPixelFormat32bppBGRA;
            break;
        case 16: This->decoder_frame.pixel_format = GUID_WICPixelFormat64bppRGBA; break;
        default:
            ERR("invalid RGBA bit depth: %i\n", bit_depth);
            hr = E_FAIL;
            goto end;
        }
        break;
    case PNG_COLOR_TYPE_GRAY:
        This->decoder_frame.bpp = bit_depth;
        if (!transparency)
        {
            switch (bit_depth)
            {
            case 1: This->decoder_frame.pixel_format = GUID_WICPixelFormatBlackWhite; break;
            case 2: This->decoder_frame.pixel_format = GUID_WICPixelFormat2bppGray; break;
            case 4: This->decoder_frame.pixel_format = GUID_WICPixelFormat4bppGray; break;
            case 8: This->decoder_frame.pixel_format = GUID_WICPixelFormat8bppGray; break;
            case 16: This->decoder_frame.pixel_format = GUID_WICPixelFormat16bppGray; break;
            default:
                ERR("invalid grayscale bit depth: %i\n", bit_depth);
                hr = E_FAIL;
                goto end;
            }
            break;
        }
        /* else fall through */
    case PNG_COLOR_TYPE_PALETTE:
        This->decoder_frame.bpp = bit_depth;
        switch (bit_depth)
        {
        case 1: This->decoder_frame.pixel_format = GUID_WICPixelFormat1bppIndexed; break;
        case 2: This->decoder_frame.pixel_format = GUID_WICPixelFormat2bppIndexed; break;
        case 4: This->decoder_frame.pixel_format = GUID_WICPixelFormat4bppIndexed; break;
        case 8: This->decoder_frame.pixel_format = GUID_WICPixelFormat8bppIndexed; break;
        default:
            ERR("invalid indexed color bit depth: %i\n", bit_depth);
            hr = E_FAIL;
            goto end;
        }
        break;
    case PNG_COLOR_TYPE_RGB:
        This->decoder_frame.bpp = bit_depth * 3;
        switch (bit_depth)
        {
        case 8:
            ppng_set_bgr(png_ptr);
            This->decoder_frame.pixel_format = GUID_WICPixelFormat24bppBGR;
            break;
        case 16: This->decoder_frame.pixel_format = GUID_WICPixelFormat48bppRGB; break;
        default:
            ERR("invalid RGB color bit depth: %i\n", bit_depth);
            hr = E_FAIL;
            goto end;
        }
        break;
    default:
        ERR("invalid color type %i\n", color_type);
        hr = E_FAIL;
        goto end;
    }

    This->decoder_frame.width = ppng_get_image_width(png_ptr, info_ptr);
    This->decoder_frame.height = ppng_get_image_height(png_ptr, info_ptr);

    ret = ppng_get_pHYs(png_ptr, info_ptr, &xres, &yres, &unit_type);

    if (ret && unit_type == PNG_RESOLUTION_METER)
    {
        This->decoder_frame.dpix = xres * 0.0254;
        This->decoder_frame.dpiy = yres * 0.0254;
    }
    else
    {
        WARN("no pHYs block present\n");
        This->decoder_frame.dpix = This->decoder_frame.dpiy = 96.0;
    }

    if (color_type == PNG_COLOR_TYPE_PALETTE)
    {
        ret = ppng_get_PLTE(png_ptr, info_ptr, &png_palette, &num_palette);
        if (!ret)
        {
            ERR("paletted image with no PLTE chunk\n");
            hr = E_FAIL;
            goto end;
        }

        if (num_palette > 256)
        {
            ERR("palette has %i colors?!\n", num_palette);
            hr = E_FAIL;
            goto end;
        }

        This->decoder_frame.num_colors = num_palette;
        for (i=0; i<num_palette; i++)
        {
            BYTE alpha = (i < num_trans) ? trans[i] : 0xff;
            This->decoder_frame.palette[i] = (alpha << 24 |
                                              png_palette[i].red << 16|
                                              png_palette[i].green << 8|
                                              png_palette[i].blue);
        }
    }
    else if (color_type == PNG_COLOR_TYPE_GRAY && transparency && bit_depth <= 8) {
        num_palette = 1 << bit_depth;

        This->decoder_frame.num_colors = num_palette;
        for (i=0; i<num_palette; i++)
        {
            BYTE alpha = (i == trans_values[0].gray) ? 0 : 0xff;
            BYTE val = i * 255 / (num_palette - 1);
            This->decoder_frame.palette[i] = (alpha << 24 | val << 16 | val << 8 | val);
        }
    }
    else
    {
        This->decoder_frame.num_colors = 0;
    }

    st->flags = WICBitmapDecoderCapabilityCanDecodeAllImages |
                WICBitmapDecoderCapabilityCanDecodeSomeImages |
                WICBitmapDecoderCapabilityCanEnumerateMetadata;
    st->frame_count = 1;

    hr = S_OK;

end:
    ppng_destroy_read_struct(&png_ptr, &info_ptr, &end_info);
    return hr;
}

HRESULT CDECL png_decoder_get_frame_info(struct decoder *iface, UINT frame, struct decoder_frame *info)
{
    struct png_decoder *This = impl_from_decoder(iface);
    *info = This->decoder_frame;
    return S_OK;
}

void CDECL png_decoder_destroy(struct decoder* iface)
{
    struct png_decoder *This = impl_from_decoder(iface);

    RtlFreeHeap(GetProcessHeap(), 0, This);
}

static const struct decoder_funcs png_decoder_vtable = {
    png_decoder_initialize,
    png_decoder_get_frame_info,
    png_decoder_destroy
};

HRESULT CDECL png_decoder_create(struct decoder_info *info, struct decoder **result)
{
    struct png_decoder *This;

    if (!load_libpng())
    {
        ERR("Failed reading PNG because unable to find %s\n",SONAME_LIBPNG);
        return E_FAIL;
    }

    This = RtlAllocateHeap(GetProcessHeap(), 0, sizeof(*This));

    if (!This)
    {
        return E_OUTOFMEMORY;
    }

    This->decoder.vtable = &png_decoder_vtable;
    *result = &This->decoder;

    info->container_format = GUID_ContainerFormatPng;
    info->block_format = GUID_ContainerFormatPng;
    info->clsid = CLSID_WICPngDecoder;

    return S_OK;
}

#else

HRESULT CDECL png_decoder_create(struct decoder_info *info, struct decoder **result)
{
    ERR("Trying to load PNG picture, but PNG support is not compiled in.\n");
    return E_FAIL;
}

#endif
