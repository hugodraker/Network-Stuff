#include <dos.h>
#include <stdlib.h>
#include <stdio.h>
#include <conio.h>

/* VESA BIOS interrupt */
#define VESA_INT 0x10

/* Mouse interrupt */
#define MOUSE_INT 0x33

/* VESA function codes */
#define VESA_MODE_INFO 0x4F01
#define VESA_SET_MODE 0x4F02
#define VESA_GET_MODES 0x4F00

/* Mode flags */
#define MODE_SUPPORTED 0x0001
#define MODE_VESA 0x0200
#define MODE_COLOR 0x0040
#define MODE_GRAPHICS 0x0010
#define MODE_LINEAR_FRAMEBUFFER 0x0080

/* Set mode mask */
#define SET_MODE_MASK 0x4000

typedef struct {
    unsigned short modeAttributes;
    unsigned char  winAAttributes;
    unsigned char  winBAttributes;
    unsigned short winGranularity;
    unsigned short winSize;
    unsigned short winASegment;
    unsigned short winBSegment;
    unsigned long  winFuncPtr;
    unsigned short bytesPerScanLine;
    unsigned short xResolution;
    unsigned short yResolution;
    unsigned char  xCharSize;
    unsigned char  yCharSize;
    unsigned char  numberOfPlanes;
    unsigned char  bitsPerPixel;
    unsigned char  numberOfBanks;
    unsigned char  memoryModel;
    unsigned char  bankSize;
    unsigned char  numberOfImagePages;
    unsigned char  reserved;
    unsigned char  redMaskSize;
    unsigned char  redFieldPosition;
    unsigned char  greenMaskSize;
    unsigned char  greenFieldPosition;
    unsigned char  blueMaskSize;
    unsigned char  blueFieldPosition;
    unsigned char  rsvdMaskSize;
    unsigned char  rsvdFieldPosition;
    unsigned long  physicalBasePtr;
} VesaModeInfo;

/* Mouse function pointers */
void (*_mouse_init)(void);
void (*_mouse_show_cursor)(int);
void (*_mouse_hide_cursor)(int);
int (*_mouse_get_position)(int *, int *, int *);
int (*_mouse_buttons)(int *);
int _mouse_installed = 0;

/* Simple mouse pointer bitmap (white on black) */
unsigned char mouse_cursor[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x7F, 0xBF, 0xDF, 0xEF, 0xF7, 0xFB, 0xFD, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

/* Screen buffer pointer */
unsigned char *video_memory = NULL;
unsigned char *saved_buffer = NULL;

/* Get VESA mode info */
int vesa_get_mode_info(unsigned short mode, VesaModeInfo *info) {
    union REGS regs;
    
    regs.x.eax = VESA_MODE_INFO;
    regs.x.edi = (unsigned long)info;
    regs.x.ebx = mode;
    
    int86(VESA_INT, &regs, &regs);
    
    return (regs.x.eax == 0x4F);
}

/* Set VESA mode */
int vesa_set_mode(unsigned short mode) {
    union REGS regs;
    
    regs.x.eax = VESA_SET_MODE;
    regs.x.ebx = mode | SET_MODE_MASK;
    
    int86(VESA_INT, &regs, &regs);
    
    return (regs.x.eax == 0x4F);
}

/* Initialize mouse driver */
int mouse_init(void) {
    union REGS regs;
    
    regs.x.eax = 0;  /* Reset mouse */
    int86(MOUSE_INT, &regs, &regs);
    
    return (regs.x.eax == 1);  /* Returns 1 if mouse installed */
}

void mouse_show(void) {
    union REGS regs;
    regs.x.eax = 1;  /* Show cursor */
    int86(MOUSE_INT, &regs, &regs);
}

void mouse_hide(void) {
    union REGS regs;
    regs.x.eax = 2;  /* Hide cursor */
    int86(MOUSE_INT, &regs, &regs);
}

void mouse_get_position(int *x, int *y, int *buttons) {
    union REGS regs;
    regs.x.eax = 3;
    int86(MOUSE_INT, &regs, &regs);
    *x = regs.x.ebx;
    *y = regs.x.ecx;
    *buttons = regs.x.edx & 0x03;
}

/* Draw cursor at position */
void draw_cursor(int x, int y) {
    int i;
    unsigned char pixel;
    
    for (i = 0; i < 32; i++) {
        if (y + i >= 480) continue;
        
        /* XOR cursor with screen (simple transparency) */
        memcpy(video_memory + ((y + i) * 640) + x, 
               mouse_cursor + (i * 16), 16);
    }
}

/* Clear cursor (restore background) */
void clear_cursor(int x, int y) {
    int i;
    
    for (i = 0; i < 32; i++) {
        if (y + i >= 480) continue;
        
        memset(video_memory + ((y + i) * 640) + x, 0, 16);
    }
}

/* Save screen area */
void save_screen_area(int x, int y, int width, int height) {
    saved_buffer = malloc(width * height);
    if (saved_buffer) {
        int i;
        for (i = 0; i < height; i++) {
            memcpy(saved_buffer + (i * width),
                   video_memory + ((y + i) * 640) + x,
                   width);
        }
    }
}

/* Restore screen area */
void restore_screen_area(int x, int y, int width, int height) {
    if (saved_buffer) {
        int i;
        for (i = 0; i < height; i++) {
            memcpy(video_memory + ((y + i) * 640) + x,
                   saved_buffer + (i * width),
                   width);
        }
        free(saved_buffer);
        saved_buffer = NULL;
    }
}

int main(void) {
    VesaModeInfo mode_info;
    int mouse_x = 100, mouse_y = 100;
    int old_x = 100, old_y = 100;
    int buttons = 0;
    int running = 1;
    
    printf("VESA 640x480x256 with Mouse Demo\n");
    printf("--------------------------------\n");
    
    /* Find VESA mode 0x103 (640x480x256) */
    if (!vesa_get_mode_info(0x103, &mode_info)) {
        printf("Error: VESA mode 0x103 not supported!\n");
        return 1;
    }
    
    printf("VESA Mode 0x103 Supported: %dx%d, %d bpp\n", 
           mode_info.xResolution, mode_info.yResolution, mode_info.bitsPerPixel);
    
    /* Set the mode */
    if (!vesa_set_mode(0x103)) {
        printf("Error: Could not set VESA mode!\n");
        return 1;
    }
    
    printf("VESA mode set successfully.\n");
    
    /* Get video memory pointer (linear framebuffer if available) */
    if (mode_info.physicalBasePtr) {
        video_memory = (unsigned char *)mode_info.physicalBasePtr;
    } else {
        printf("Warning: No linear framebuffer, using segmented access\n");
        video_memory = (unsigned char *)0xA0000000L;  /* Fallback */
    }
    
    /* Clear screen to black */
    memset(video_memory, 0, 640 * 480);
    
    /* Initialize mouse */
    if (!mouse_init()) {
        printf("Warning: Mouse driver not found!\n");
    } else {
        printf("Mouse driver initialized.\n");
        mouse_show();
    }
    
    /* Main loop */
    while (running) {
        /* Get mouse position */
        int mx, my;
        mouse_get_position(&mx, &my, &buttons);
        
        /* Update cursor position if moved */
        if (mx != mouse_x || my != mouse_y) {
            /* Clear old position */
            if (old_x >= 0 && old_x < 608 && old_y >= 0 && old_y < 448) {
                clear_cursor(old_x, old_y);
            }
            
            /* Store new position */
            old_x = mouse_x = mx;
            old_y = mouse_y = my;
            
            /* Draw cursor at new position */
            if (mouse_x >= 0 && mouse_x < 608 && mouse_y >= 0 && mouse_y < 448) {
                draw_cursor(mouse_x, mouse_y);
            }
        }
        
        /* Check for quit condition (ESC key) */
        if (kbhit() && getch() == 27) {
            running = 0;
        }
        
        /* Small delay to prevent CPU hogging */
        usleep(1000);
    }
    
    /* Cleanup */
    mouse_hide();
    vesa_set_mode(3);  /* Return to text mode */
    
    printf("\nProgram terminated normally.\n");
    return 0;
}