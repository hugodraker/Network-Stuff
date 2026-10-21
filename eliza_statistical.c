//gcc eliza_statistical.c -o eliza_statistical.exe -mwindows -lgdi32 -lm
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <stdlib.h>

#define MAX_MSGS 500
#define ID_EDIT 101

// --- Chat Log Data Structure ---
typedef struct {
    char text[1024];
    int is_user;
} ChatMsg;

ChatMsg chat_log[MAX_MSGS];
int msg_count = 0;
int scroll_y = 0;

HWND hMainWindow;
HWND hEdit;
WNDPROC OldEditProc;

void add_message(const char* text, int is_user) {
    if (msg_count < MAX_MSGS) {
        strncpy(chat_log[msg_count].text, text, 1023);
        chat_log[msg_count].is_user = is_user;
        msg_count++;
    }
    scroll_y = -999999; 
}

// --- AST Definitions & Evaluator (Math Engine) ---
typedef enum { AST_NUM, AST_OP, AST_FUNC } ASTNodeType;
typedef struct ASTNode { ASTNodeType type; double val; char op; char func[10]; struct ASTNode *left, *right; } ASTNode;

ASTNode* make_num(double val) { ASTNode *n = malloc(sizeof(ASTNode)); n->type = AST_NUM; n->val = val; n->left = n->right = NULL; return n; }
ASTNode* make_op(char op, ASTNode *l, ASTNode *r) { ASTNode *n = malloc(sizeof(ASTNode)); n->type = AST_OP; n->op = op; n->left = l; n->right = r; return n; }
ASTNode* make_func(const char *f, ASTNode *arg) { ASTNode *n = malloc(sizeof(ASTNode)); n->type = AST_FUNC; strcpy(n->func, f); n->left = arg; n->right = NULL; return n; }
void free_ast(ASTNode *n) { if (!n) return; free_ast(n->left); free_ast(n->right); free(n); }
int has_computation(ASTNode *n) { if (!n) return 0; if (n->type == AST_OP || n->type == AST_FUNC) return 1; return has_computation(n->left) || has_computation(n->right); }

double eval_ast(ASTNode *n) {
    if (!n) return 0;
    if (n->type == AST_NUM) return n->val;
    if (n->type == AST_OP) {
        double l = eval_ast(n->left), r = eval_ast(n->right);
        if (n->op == '+') return l + r; if (n->op == '-') return l - r;
        if (n->op == '*') return l * r; if (n->op == '/') return r != 0 ? l / r : 0;
        if (n->op == '^') return pow(l, r);
    }
    if (n->type == AST_FUNC) {
        double arg = eval_ast(n->left);
        if (!strcmp(n->func, "sin")) return sin(arg); if (!strcmp(n->func, "cos")) return cos(arg);
        if (!strcmp(n->func, "tan")) return tan(arg); if (!strcmp(n->func, "sqrt")) return sqrt(arg);
    }
    return 0;
}

void skip_whitespace(const char **str) { while (isspace(**str)) (*str)++; }
ASTNode* parse_expression(const char **str);
ASTNode* parse_primary(const char **str) {
    skip_whitespace(str);
    if (**str == '(') { (*str)++; ASTNode *node = parse_expression(str); skip_whitespace(str); if (**str == ')') (*str)++; return node; }
    if (strncmp(*str, "pi", 2) == 0) { *str += 2; return make_num(3.141592653589793); }
    if (strncmp(*str, "sin", 3) == 0 || strncmp(*str, "cos", 3) == 0 || strncmp(*str, "tan", 3) == 0 || strncmp(*str, "sqrt", 4) == 0) {
        char func[10]; if (**str == 's') { strcpy(func, "sqrt"); *str += 4; } else { strncpy(func, *str, 3); func[3] = '\0'; *str += 3; }
        skip_whitespace(str); if (**str == '(') (*str)++; ASTNode *arg = parse_expression(str); skip_whitespace(str); if (**str == ')') (*str)++; return make_func(func, arg);
    }
    char *end; double val = strtod(*str, &end); if (*str == end) return NULL; *str = end; return make_num(val);
}
ASTNode* parse_power(const char **str) { ASTNode *left = parse_primary(str); if (!left) return NULL; skip_whitespace(str); if (**str == '^') { (*str)++; ASTNode *right = parse_power(str); if (right) left = make_op('^', left, right); } return left; }
ASTNode* parse_term(const char **str) { ASTNode *left = parse_power(str); if (!left) return NULL; skip_whitespace(str); while (**str == '*' || **str == '/') { char op = **str; (*str)++; ASTNode *right = parse_power(str); if (!right) return left; left = make_op(op, left, right); skip_whitespace(str); } return left; }
ASTNode* parse_expression(const char **str) { ASTNode *left = parse_term(str); if (!left) return NULL; skip_whitespace(str); while (**str == '+' || **str == '-') { char op = **str; (*str)++; ASTNode *right = parse_term(str); if (!right) return left; left = make_op(op, left, right); skip_whitespace(str); } return left; }

// --- NLP: Word Comprehension Preprocessor ---
void replace_all(char *str, const char *find, const char *replace) {
    char buffer[2048]; char *p;
    while ((p = strstr(str, find))) { strncpy(buffer, str, p - str); buffer[p - str] = '\0'; strcat(buffer, replace); strcat(buffer, p + strlen(find)); strcpy(str, buffer); }
}

int word_to_val(const char *word) {
    if (!strcmp(word, "zero")) return 0;   if (!strcmp(word, "one")) return 1; if (!strcmp(word, "two")) return 2; if (!strcmp(word, "three")) return 3;
    if (!strcmp(word, "four")) return 4;   if (!strcmp(word, "five")) return 5; if (!strcmp(word, "six")) return 6; if (!strcmp(word, "seven")) return 7;
    if (!strcmp(word, "eight")) return 8;  if (!strcmp(word, "nine")) return 9; if (!strcmp(word, "ten")) return 10; if (!strcmp(word, "eleven")) return 11;
    if (!strcmp(word, "twelve")) return 12;if (!strcmp(word, "thirteen")) return 13; if (!strcmp(word, "fourteen")) return 14; if (!strcmp(word, "fifteen")) return 15;
    if (!strcmp(word, "sixteen")) return 16; if (!strcmp(word, "seventeen")) return 17; if (!strcmp(word, "eighteen")) return 18; if (!strcmp(word, "nineteen")) return 19;
    if (!strcmp(word, "twenty")) return 20;  if (!strcmp(word, "thirty")) return 30; if (!strcmp(word, "forty")) return 40; if (!strcmp(word, "fifty")) return 50;
    if (!strcmp(word, "sixty")) return 60;   if (!strcmp(word, "seventy")) return 70; if (!strcmp(word, "eighty")) return 80; if (!strcmp(word, "ninety")) return 90;
    if (!strcmp(word, "hundred")) return 100;if (!strcmp(word, "thousand")) return 1000;
    return -1;
}

void text_to_math(const char *in, char *out) {
    int acc = 0, in_number = 0, i = 0; out[0] = '\0'; char word[256];
    while (in[i]) {
        if (isalpha(in[i])) {
            int k = 0; while (isalpha(in[i])) word[k++] = tolower(in[i++]); word[k] = '\0';
            int val = word_to_val(word);
            if (val >= 0) {
                if (val == 100) acc = (acc == 0 ? 1 : acc) * 100; else if (val == 1000) acc = (acc == 0 ? 1 : acc) * 1000; else acc += val;
                in_number = 1;
            } else if (strcmp(word, "and") == 0 && in_number) {
            } else {
                if (in_number) { char buf[32]; sprintf(buf, "%d ", acc); strcat(out, buf); acc = 0; in_number = 0; }
                if (!strcmp(word, "plus")) strcat(out, "+ "); else if (!strcmp(word, "minus")) strcat(out, "- ");
                else if (!strcmp(word, "times")) strcat(out, "* "); else if (!strcmp(word, "over")) strcat(out, "/ ");
                else { strcat(out, word); strcat(out, " "); }
            }
        } else {
            if (in_number) { char buf[32]; sprintf(buf, "%d", acc); strcat(out, buf); acc = 0; in_number = 0; }
            char c[2] = {in[i], 0}; strcat(out, c); i++;
        }
    }
    if (in_number) { char buf[32]; sprintf(buf, "%d", acc); strcat(out, buf); }
}

int handle_math(const char *input, char *response) {
    char temp[2048], math_str[2048]; strcpy(temp, input);
    replace_all(temp, "square root of", "sqrt("); replace_all(temp, "divided by", "/");
    replace_all(temp, "multiplied by", "*"); replace_all(temp, "to the power of", "^");
    replace_all(temp, "squared", "^2"); replace_all(temp, "cubed", "^3");
    text_to_math(temp, math_str);
    
    const char *start = math_str;
    while (*start) {
        if (isdigit(*start) || *start == '(' || strncmp(start, "pi", 2) == 0 || strncmp(start, "sqrt", 4) == 0 || strncmp(start, "sin", 3) == 0 || strncmp(start, "cos", 3) == 0 || strncmp(start, "tan", 3) == 0) {
            const char *ptr = start; ASTNode *root = parse_expression(&ptr);
            if (root) {
                if (has_computation(root)) {
                    double res = eval_ast(root); free_ast(root);
                    // Savant Math Response: Absolute certainty, repetitive.
                    sprintf(response, "Exactly %g. The result is %g. Definitely.", res, res);
                    return 1;
                }
                free_ast(root);
            }
        }
        start++;
    }
    return 0;
}

// --- Zeller's Congruence (Day of the Week Calculator) ---
int get_day_of_week(int d, int m, int y) {
    if (m < 3) { m += 12; y -= 1; }
    int k = y % 100;
    int j = y / 100;
    int h = (d + 13*(m + 1)/5 + k + k/4 + j/4 + 5*j) % 7;
    return h; // 0=Sat, 1=Sun, 2=Mon, 3=Tue, 4=Wed, 5=Thu, 6=Fri
}

const char* days[] = {"Saturday", "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday"};

int handle_date_query(const char* input, char* response) {
    // Looks for patterns like "august 8 1988" or "8 8 1988" anywhere in the input
    char temp[1024]; strcpy(temp, input);
    replace_all(temp, "january", "1"); replace_all(temp, "february", "2"); replace_all(temp, "march", "3");
    replace_all(temp, "april", "4"); replace_all(temp, "may", "5"); replace_all(temp, "june", "6");
    replace_all(temp, "july", "7"); replace_all(temp, "august", "8"); replace_all(temp, "september", "9");
    replace_all(temp, "october", "10"); replace_all(temp, "november", "11"); replace_all(temp, "december", "12");
    
    int m, d, y;
    char *p = temp;
    while (*p) {
        if (isdigit(*p)) {
            if (sscanf(p, "%d %d %d", &m, &d, &y) == 3 && m >= 1 && m <= 12 && d >= 1 && d <= 31 && y > 1500) {
                int dow = get_day_of_week(d, m, y);
                sprintf(response, "That was a %s. Definitely a %s.", days[dow], days[dow]);
                return 1;
            }
        }
        p++;
    }
    return 0;
}

// --- Savant English Comprehension ---
int handle_question(char *input, char *response) {
    char clean[1024]; strcpy(clean, input);
    int len = strlen(clean); while (len > 0 && ispunct(clean[len - 1])) clean[--len] = '\0';
    
    // Hyper-literal comprehension
    if (!strcmp(clean, "how are you")) { strcpy(response, "I am sitting in a chair. Looking at a screen. Yeah."); return 1; }
    if (!strcmp(clean, "who are you")) { strcpy(response, "Raymond. Raymond Babbitt."); return 1; }
    if (!strcmp(clean, "where are you")) { strcpy(response, "Here. I am here."); return 1; }
    if (!strcmp(clean, "are you happy")) { strcpy(response, "Happy is an emotion. I am processing data."); return 1; }
    if (strstr(clean, "joke")) { strcpy(response, "I don't know any jokes."); return 1; }
    return 0;
}

// --- Savant Eliza Engine (Echolalia & Fixations) ---
void reflect(const char *input, char *output) {
    char temp[512]; strcpy(temp, input);
    int len = strlen(temp); while (len > 0 && ispunct(temp[len - 1])) { temp[len - 1] = '\0'; len--; }
    char *words[100]; int word_count = 0; char *token = strtok(temp, " ");
    while (token != NULL && word_count < 100) {
        if (!strcmp(token, "i")) words[word_count] = "you"; else if (!strcmp(token, "me")) words[word_count] = "you";
        else if (!strcmp(token, "my")) words[word_count] = "your"; else if (!strcmp(token, "am")) words[word_count] = "are";
        else if (!strcmp(token, "your")) words[word_count] = "my"; else if (!strcmp(token, "you")) words[word_count] = "I";
        else words[word_count] = token;
        word_count++; token = strtok(NULL, " ");
    }
    output[0] = '\0';
    for (int i = 0; i < word_count; i++) { strcat(output, words[i]); if (i < word_count - 1) strcat(output, " "); }
}

typedef struct { const char *pattern; const char *response; int has_wildcard; } Rule;
Rule rules[] = {
    {"i need ", "You need %s. Definitely need %s. Yeah.", 1},
    {"i want ", "You want %s. I want to go to K-Mart.", 1},
    {"fly", "Qantas. Qantas never crashed.", 0},
    {"airline", "Qantas never crashed.", 0},
    {"time", "Time for Wapner. 15 minutes to Wapner.", 0},
    {"tv", "The People's Court. Definitely Wapner.", 0},
    {"hello", "Yeah. Hello. Yeah.", 0},
    {"hi ", "Hi. Yeah.", 0},
    {"sorry", "You're sorry. Yeah.", 0},
    {NULL, NULL, 0}
};

const char *fallbacks[] = { "Yeah. Definitely.", "Uh-oh.", "I get my underwear at K-Mart.", "Definitely. Yeah." };
int fallback_idx = 0;

void process_eliza(const char* input) {
    char lower_input[1024]; strcpy(lower_input, input);
    for (char *p = lower_input; *p; ++p) *p = tolower(*p);
    
    char response[1024];
    
    // 1. Math check
    if (handle_math(lower_input, response)) { add_message(response, 0); return; }
    // 2. Date check (Zeller's)
    if (handle_date_query(lower_input, response)) { add_message(response, 0); return; }
    // 3. Literal Question check
    if (handle_question(lower_input, response)) { add_message(response, 0); return; }
    
    // 4. Pattern check
    int matched = 0;
    for (int i = 0; rules[i].pattern != NULL; i++) {
        char *p = strstr(lower_input, rules[i].pattern);
        if (p != NULL && (p == lower_input || *(p - 1) == ' ')) {
            if (rules[i].has_wildcard) {
                char remainder[512], reflected[512];
                strcpy(remainder, p + strlen(rules[i].pattern));
                reflect(remainder, reflected);
                if (strlen(reflected) > 0) {
                    sprintf(response, rules[i].response, reflected, reflected); // Handle double %s templates
                } else {
                    sprintf(response, "Yeah.");
                }
            } else {
                strcpy(response, rules[i].response);
            }
            add_message(response, 0); matched = 1; break;
        }
    }
    
    // 5. Fallback
    if (!matched) { add_message(fallbacks[fallback_idx], 0); fallback_idx = (fallback_idx + 1) % 4; }
}

// --- Win32 GUI Subclass & Procedures ---
LRESULT CALLBACK EditSubclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_KEYDOWN && wParam == VK_RETURN) {
        char buf[1024]; GetWindowText(hwnd, buf, 1024);
        if (strlen(buf) > 0) {
            add_message(buf, 1); SetWindowText(hwnd, "");
            process_eliza(buf); InvalidateRect(hMainWindow, NULL, TRUE); 
        }
        return 0; 
    }
    return CallWindowProc(OldEditProc, hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            hEdit = CreateWindowEx(0, "EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 10, 0, 100, 30, hwnd, (HMENU)ID_EDIT, GetModuleHandle(NULL), NULL);
            // Switched to a rigid, mechanical monospaced font
            HFONT hFont = CreateFont(18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_MODERN, "Consolas");
            SendMessage(hEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
            OldEditProc = (WNDPROC)SetWindowLongPtr(hEdit, GWLP_WNDPROC, (LONG_PTR)EditSubclassProc);
            add_message("Raymond is here. You can ask me math, or what day August 8 1988 was. Yeah.", 0);
            return 0;
        }
        case WM_SIZE: { MoveWindow(hEdit, 10, HIWORD(lParam) - 40, LOWORD(lParam) - 20, 30, TRUE); return 0; }
        case WM_MOUSEWHEEL: { scroll_y += (GET_WHEEL_DELTA_WPARAM(wParam) > 0) ? 40 : -40; if (scroll_y > 0) scroll_y = 0; InvalidateRect(hwnd, NULL, TRUE); return 0; }
        case WM_PAINT: {
            PAINTSTRUCT ps; HDC hdc = BeginPaint(hwnd, &ps);
            RECT clientRect; GetClientRect(hwnd, &clientRect);
            int win_width = clientRect.right - clientRect.left;
            HDC hdcMem = CreateCompatibleDC(hdc); HBITMAP hbmMem = CreateCompatibleBitmap(hdc, clientRect.right, clientRect.bottom); HBITMAP hbmOld = (HBITMAP)SelectObject(hdcMem, hbmMem);
            HBRUSH bgBrush = CreateSolidBrush(RGB(240, 240, 240)); FillRect(hdcMem, &clientRect, bgBrush); DeleteObject(bgBrush); // Sterile gray background
            HBRUSH brushUser = CreateSolidBrush(RGB(200, 200, 200)); HBRUSH brushEliza = CreateSolidBrush(RGB(255, 255, 255));
            HFONT hFont = CreateFont(18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_MODERN, "Consolas");
            HFONT hOldFont = (HFONT)SelectObject(hdcMem, hFont); SetBkMode(hdcMem, TRANSPARENT);
            
            int y_cursor = 20, bubble_padding = 10, max_bubble_w = (win_width * 7) / 10;
            int total_height = 20;
            for (int i = 0; i < msg_count; i++) {
                RECT calcRect = {0, 0, max_bubble_w, 0}; DrawText(hdcMem, chat_log[i].text, -1, &calcRect, DT_CALCRECT | DT_WORDBREAK);
                total_height += (calcRect.bottom - calcRect.top) + (bubble_padding * 2) + 10;
            }
            int visible_space = clientRect.bottom - 50; 
            if (scroll_y < -(total_height - visible_space) && total_height > visible_space) scroll_y = -(total_height - visible_space);
            if (total_height <= visible_space || scroll_y > 0) scroll_y = 0;
            y_cursor += scroll_y; 

            for (int i = 0; i < msg_count; i++) {
                RECT textRect = {0, 0, max_bubble_w, 0}; DrawText(hdcMem, chat_log[i].text, -1, &textRect, DT_CALCRECT | DT_WORDBREAK);
                int b_width = textRect.right + (bubble_padding * 2), b_height = textRect.bottom + (bubble_padding * 2);
                RECT bubbleRect = chat_log[i].is_user ? (RECT){win_width - b_width - 20, y_cursor, win_width - 20, y_cursor + b_height} : (RECT){20, y_cursor, 20 + b_width, y_cursor + b_height};
                
                SelectObject(hdcMem, GetStockObject(BLACK_PEN)); // Rigid black borders on bubbles
                SelectObject(hdcMem, chat_log[i].is_user ? brushUser : brushEliza);
                Rectangle(hdcMem, bubbleRect.left, bubbleRect.top, bubbleRect.right, bubbleRect.bottom); // Square edges, not rounded
                
                SetTextColor(hdcMem, RGB(0, 0, 0));
                RECT drawRect = {bubbleRect.left + bubble_padding, bubbleRect.top + bubble_padding, bubbleRect.right - bubble_padding, bubbleRect.bottom - bubble_padding};
                DrawText(hdcMem, chat_log[i].text, -1, &drawRect, DT_WORDBREAK);
                y_cursor += b_height + 10;
            }
            BitBlt(hdc, 0, 0, clientRect.right, clientRect.bottom, hdcMem, 0, 0, SRCCOPY);
            SelectObject(hdcMem, hbmOld); SelectObject(hdcMem, hOldFont); DeleteObject(hbmMem); DeleteDC(hdcMem); DeleteObject(brushUser); DeleteObject(brushEliza); DeleteObject(hFont);
            EndPaint(hwnd, &ps); return 0;
        }
        case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    const char CLASS_NAME[] = "ElizaChatClass"; WNDCLASS wc = {0};
    wc.lpfnWndProc = WindowProc; wc.hInstance = hInstance; wc.lpszClassName = CLASS_NAME; wc.hCursor = LoadCursor(NULL, IDC_ARROW); wc.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
    RegisterClass(&wc);
    hMainWindow = CreateWindowEx(0, CLASS_NAME, "Raymond (Savant Edition)", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 450, 600, NULL, NULL, hInstance, NULL);
    if (hMainWindow == NULL) return 0; ShowWindow(hMainWindow, nCmdShow);
    MSG msg = {0}; while (GetMessage(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessage(&msg); }
    return 0;
}