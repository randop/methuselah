#include "methuselah/ui_session.hpp"

#include "config.h"
#include "hack_font.h"
#include "methuselah/secure_memory.hpp"
#include "methuselah/signal_guard.hpp"
#include "shader_sdf.h"

#include "raylib.h"

#define RAYGUI_IMPLEMENTATION
#include "raygui.h"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <iostream>
#include <memory>

namespace methuselah {
namespace {

void raylib_log_callback(int log_level, const char *text, va_list args) {
  const char *prefix = nullptr;
  switch (log_level) {
  case LOG_TRACE:
    prefix = "TRACE";
    break;
  case LOG_DEBUG:
    prefix = "DEBUG";
    break;
  case LOG_INFO:
    prefix = "INFO";
    break;
  case LOG_WARNING:
    prefix = "WARN";
    break;
  case LOG_ERROR:
    prefix = "ERROR";
    break;
  case LOG_FATAL:
    prefix = "FATAL";
    break;
  default:
    prefix = "?";
    break;
  }

  char formatted[1024];
  vsnprintf(formatted, sizeof(formatted), text, args);
  SPDLOG_TRACE("<{}> {}", prefix, formatted);
  (void)prefix;
}

void raylib_debug_callback(int log_level, const char *text, va_list args) {
  const char *prefix = nullptr;
  switch (log_level) {
  case LOG_TRACE:
    prefix = "TRACE";
    break;
  case LOG_DEBUG:
    prefix = "DEBUG";
    break;
  case LOG_INFO:
    prefix = "INFO";
    break;
  case LOG_WARNING:
    prefix = "WARN";
    break;
  case LOG_ERROR:
    prefix = "ERROR";
    break;
  case LOG_FATAL:
    prefix = "FATAL";
    break;
  default:
    prefix = "?";
    break;
  }

  char formatted[2048];
  vsnprintf(formatted, sizeof(formatted), text, args);
  SPDLOG_INFO("<{}> {}", prefix, formatted);
}

struct PasswordPromptLayout {
  Rectangle message{};
  Rectangle input{};
  Rectangle reveal{};
  Rectangle continue_button{};
  Rectangle cancel_button{};
};

PasswordPromptLayout password_prompt_layout(Rectangle window,
                                            const char *message) {
  constexpr float kStatusBarHeight = 24.0f;
  constexpr float kButtonHeight = 24.0f;
  constexpr float kButtonPadding = 12.0f;
  constexpr float kInputHeight = 26.0f;
  constexpr float kRevealGap = 4.0f;

  const int text_size = GuiGetStyle(DEFAULT, TEXT_SIZE);
  const int message_input_height = static_cast<int>(
      window.height - kStatusBarHeight - GuiGetStyle(STATUSBAR, BORDER_WIDTH) -
      kButtonHeight - 2.0f * kButtonPadding);

  PasswordPromptLayout layout;
  if (message != nullptr) {
    const int message_width = GuiGetTextWidth(message) + 2;
    layout.message = {window.x + window.width / 2.0f - message_width / 2.0f,
                      window.y + kStatusBarHeight +
                          message_input_height / 4.0f - text_size / 2.0f,
                      static_cast<float>(message_width),
                      static_cast<float>(text_size)};
  }

  layout.input.x = window.x + kButtonPadding;
  layout.input.y = window.y + kStatusBarHeight - kInputHeight / 2.0f;
  if (message == nullptr) {
    layout.input.y = window.y + kStatusBarHeight + kButtonPadding;
  } else {
    layout.input.y +=
        static_cast<float>(message_input_height / 2 + message_input_height / 4);
  }
  layout.input.width = window.width - 2.0f * kButtonPadding;
  layout.input.height = kInputHeight;

  layout.reveal = {layout.input.x + layout.input.width - kInputHeight,
                   layout.input.y, kInputHeight, kInputHeight};
  layout.input.width -= kRevealGap + kInputHeight;

  const float button_y =
      window.y + window.height - kButtonHeight - kButtonPadding;
  const float button_width = (window.width - 3.0f * kButtonPadding) / 2.0f;
  layout.continue_button = {window.x + kButtonPadding, button_y, button_width,
                            kButtonHeight};
  layout.cancel_button = {layout.continue_button.x + button_width +
                              kButtonPadding,
                          button_y, button_width, kButtonHeight};

  return layout;
}

void draw_password_overlay(Rectangle input, const char *password,
                           Color background) {
  if (password == nullptr || password[0] == '\0') {
    return;
  }

  const float border = static_cast<float>(GuiGetStyle(TEXTBOX, BORDER_WIDTH));
  const float padding = static_cast<float>(GuiGetStyle(TEXTBOX, TEXT_PADDING));
  const float available_width = input.width - 2.0f * (border + padding);
  if (available_width <= 0.0f) {
    return;
  }

  const float text_width = static_cast<float>(GuiGetTextWidth(password));
  const Rectangle overlay{input.x + border + padding, input.y + border,
                          std::min(text_width, available_width),
                          input.height - 2.0f * border};
  DrawRectangleRec(overlay, Fade(background, 0.9f));
}

} // namespace

struct UiSession::Impl {
  Font font{};
  float screen_width = 0.0f;
  float screen_height = 0.0f;
  bool ready = false;
  bool font_loaded = false;
};

UiSession::UiSession() : impl_(std::make_unique<Impl>()) {
  SetConfigFlags(FLAG_WINDOW_UNDECORATED | FLAG_VSYNC_HINT | FLAG_MSAA_4X_HINT |
                 FLAG_WINDOW_HIGHDPI);
  InitWindow(800, 600, PROJECT_NAME);

  if (!IsWindowReady()) {
    std::cerr << "ERROR: Failed to initialize window" << std::endl;
    return;
  }

  const int mon = GetCurrentMonitor();
  impl_->screen_width = static_cast<float>(GetMonitorWidth(mon));
  impl_->screen_height = static_cast<float>(GetMonitorHeight(mon));

  SetWindowPosition(0, 0);
  SetWindowSize(static_cast<int>(impl_->screen_width),
                static_cast<int>(impl_->screen_height));

  SetTargetFPS(60);
  SetWindowTitle(PROJECT_NAME);

  constexpr int kFontBaseSize = 96;
  constexpr int kFontGlyphCount = 224;
  int codepoints[kFontGlyphCount];
  for (int i = 0; i < kFontGlyphCount; i++) {
    codepoints[i] = 32 + i;
  }
  impl_->font = LoadFontFromMemory(".ttf", HACK_REGULAR_TTF,
                                   static_cast<int>(HACK_REGULAR_TTF_SIZE),
                                   kFontBaseSize, codepoints, kFontGlyphCount);
  SetTextureFilter(impl_->font.texture, TEXTURE_FILTER_BILINEAR);
  GenTextureMipmaps(&impl_->font.texture);
  SetTextureFilter(impl_->font.texture, TEXTURE_FILTER_TRILINEAR);
  impl_->font_loaded = true;

  Vector2 dpiScale = GetWindowScaleDPI();
  float uiScale = dpiScale.x;

  GuiSetFont(impl_->font);
  GuiSetStyle(DEFAULT, TEXT_SIZE, (int)(24 * uiScale));
  GuiSetStyle(DEFAULT, TEXT_PADDING, 12);

  impl_->ready = true;
}

UiSession::~UiSession() {
  if (!impl_) {
    return;
  }
  if (impl_->font_loaded) {
    UnloadFont(impl_->font);
    impl_->font_loaded = false;
  }
  if (IsWindowReady()) {
    CloseWindow();
  }
}

UiSession::UiSession(UiSession &&) noexcept = default;
UiSession &UiSession::operator=(UiSession &&) noexcept = default;

void UiSession::silence_trace_logs() { SetTraceLogLevel(LOG_NONE); }

void UiSession::install_log_callback() {
  SetTraceLogCallback(raylib_log_callback);
}

void UiSession::install_debug_callback() {
  SetTraceLogCallback(raylib_debug_callback);
}

bool UiSession::ready() const noexcept { return impl_ && impl_->ready; }

std::optional<std::string>
UiSession::prompt_password(const PromptOptions &options) {
  if (!ready()) {
    return std::nullopt;
  }

  Shader sdfShader = LoadShaderFromMemory(NULL, SHADER_SDF);

  SecureArray<256> password_buf;
  bool reveal_password = false;
  bool edit_mode = false;
  int result = 0; // 0 = open, 1 = OK, -1 = Cancel/timeout/window close
  const double start = GetTime();

  const Rectangle box{impl_->screen_width / 2 - 300,
                      impl_->screen_height / 2 - 125, 600, 250};
  const PasswordPromptLayout layout =
      password_prompt_layout(box, options.message.c_str());

  while (!WindowShouldClose() && result == 0 && !SignalGuard::received()) {
    if (options.timeout_seconds > 0 &&
        (GetTime() - start) > static_cast<double>(options.timeout_seconds)) {
      result = -1;
      break;
    }

    BeginDrawing();
    ClearBackground(GetColor(GuiGetStyle(DEFAULT, BACKGROUND_COLOR)));

    BeginShaderMode(sdfShader);
    DrawTextEx(impl_->font, PROJECT_TAG, {40.0f, 40.0f}, 48.0f, 1.0f, DARKBLUE);
    DrawFPS(impl_->screen_width - 120, 20);

    // GuiTextInputBox() reveals the raw password while it is being edited, so
    // draw the dialog here with a hidden text field and an overlay instead.
    if (GuiWindowBox(box, options.title.c_str()) != 0) {
      result = -1;
    }

    if (layout.message.width > 0.0f) {
      const int previous_alignment = GuiGetStyle(LABEL, TEXT_ALIGNMENT);
      GuiSetStyle(LABEL, TEXT_ALIGNMENT, TEXT_ALIGN_CENTER);
      GuiLabel(layout.message, options.message.c_str());
      GuiSetStyle(LABEL, TEXT_ALIGNMENT, previous_alignment);
    }

    const int previous_text_alignment = GuiGetStyle(TEXTBOX, TEXT_ALIGNMENT);
    GuiSetStyle(TEXTBOX, TEXT_ALIGNMENT, TEXT_ALIGN_LEFT);

    // Prevent plaintext from being drawn outside the overlay at any font size.
    constexpr int text_colors[] = {TEXT_COLOR_NORMAL, TEXT_COLOR_FOCUSED,
                                   TEXT_COLOR_PRESSED, TEXT_COLOR_DISABLED};
    int previous_text_colors[4];
    if (!reveal_password) {
      for (int i = 0; i < 4; ++i) {
        previous_text_colors[i] = GuiGetStyle(TEXTBOX, text_colors[i]);
        GuiSetStyle(TEXTBOX, text_colors[i], 0);
      }
    }

    if (GuiTextBox(layout.input, password_buf.data(), password_buf.size(),
                   edit_mode)) {
      edit_mode = !edit_mode;
    }

    if (!reveal_password) {
      for (int i = 0; i < 4; ++i) {
        GuiSetStyle(TEXTBOX, text_colors[i], previous_text_colors[i]);
      }
      const Color background =
          edit_mode ? GetColor(GuiGetStyle(TEXTBOX, BASE_COLOR_PRESSED))
                    : GetColor(GuiGetStyle(DEFAULT, BACKGROUND_COLOR));
      draw_password_overlay(layout.input, password_buf.data(), background);
    }

    GuiSetStyle(TEXTBOX, TEXT_ALIGNMENT, previous_text_alignment);

    GuiToggle(layout.reveal,
              reveal_password ? GuiIconText(ICON_EYE_ON, NULL)
                              : GuiIconText(ICON_EYE_OFF, NULL),
              &reveal_password);

    if (GuiButton(layout.continue_button, "Continue")) {
      result = 1;
    }
    if (GuiButton(layout.cancel_button, "Cancel")) {
      result = -1;
    }

    EndShaderMode();
    EndDrawing();
  }

  UnloadShader(sdfShader);

  if (result != 1) {
    return std::nullopt;
  }

  return std::string(password_buf.data());
}

} // namespace methuselah
