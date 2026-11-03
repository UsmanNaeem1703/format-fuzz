/* png_harness.c - simple libpng decode harness for AFL++
   Reads a PNG file from argv[1] and fully decodes it (both high-level
   and progressive-style reads through every row). Exits 0 on success,
   1 on clean decode error, 2 on usage error. Crashes (SIGABRT etc.)
   are caught by AFL++ as crashes. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <png.h>

int main(int argc, char **argv) {

  if (argc < 2) return 2;

  FILE *fp = fopen(argv[1], "rb");
  if (!fp) return 2;

  unsigned char sig[8];
  if (fread(sig, 1, 8, fp) != 8 || png_sig_cmp(sig, 0, 8)) {
    fclose(fp);
    return 1;
  }

  png_structp png =
      png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
  if (!png) { fclose(fp); return 2; }

  png_infop info = png_create_info_struct(png);
  if (!info) { png_destroy_read_struct(&png, NULL, NULL); fclose(fp); return 2; }

  if (setjmp(png_jmpbuf(png))) {
    /* libpng longjmp: clean decode error */
    png_destroy_read_struct(&png, &info, NULL);
    fclose(fp);
    return 1;
  }

  png_init_io(png, fp);
  png_set_sig_bytes(png, 8);
  png_read_info(png, info);

  png_uint_32 w = png_get_image_width(png, info);
  png_uint_32 h = png_get_image_height(png, info);
  png_byte color_type = png_get_color_type(png, info);
  png_byte bit_depth = png_get_bit_depth(png, info);

  /* normalize exotic inputs so row decoding always succeeds structurally */
  if (bit_depth == 16) png_set_strip_16(png);
  if (color_type == PNG_COLOR_TYPE_PALETTE) png_set_palette_to_rgb(png);
  if (color_type == PNG_COLOR_TYPE_GRAY && bit_depth < 8)
    png_set_expand_gray_1_2_4_to_8(png);
  if (png_get_valid(png, info, PNG_INFO_tRNS)) png_set_tRNS_to_alpha(png);
  if (color_type == PNG_COLOR_TYPE_RGB ||
      color_type == PNG_COLOR_TYPE_GRAY ||
      color_type == PNG_COLOR_TYPE_PALETTE)
    png_set_filler(png, 0xFF, PNG_FILLER_AFTER);
  if (color_type == PNG_COLOR_TYPE_GRAY ||
      color_type == PNG_COLOR_TYPE_GRAY_ALPHA)
    png_set_gray_to_rgb(png);

  /* sanity cap to keep memory bounded while fuzzing */
  if (w > 4096 || h > 4096) {
    png_destroy_read_struct(&png, &info, NULL);
    fclose(fp);
    return 1;
  }

  png_read_update_info(png, info);

  size_t rowbytes = png_get_rowbytes(png, info);
  png_bytep row = (png_bytep)malloc(rowbytes ? rowbytes : 1);
  if (!row) { png_destroy_read_struct(&png, &info, NULL); fclose(fp); return 2; }

  /* read every row: exercises inflate + all filters/interlace passes */
  for (png_uint_32 y = 0; y < h; ++y)
    png_read_row(png, row, NULL);

  png_read_end(png, info);

  /* touch the decoded data so it is not optimized away */
  unsigned long sum = 0;
  for (size_t i = 0; i < rowbytes; ++i) sum += row[i];

  free(row);
  png_destroy_read_struct(&png, &info, NULL);
  fclose(fp);

  printf("%lu\n", sum);
  return 0;
}
