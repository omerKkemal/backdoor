import os
import subprocess
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.textinput import TextInput
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.core.window import Window
from kivy.properties import StringProperty
from kivy.clock import Clock

# Optional: for desktop testing
Window.size = (360, 640)

class Terminal(BoxLayout):
    output_text = StringProperty("Welcome to Kivy Terminal Emulator\n")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.padding = 5
        self.spacing = 5

        # Scrollable output area
        self.scroll = ScrollView(size_hint=(1, 0.9), bar_width=4)
        self.output_label = Label(
            text=self.output_text,
            markup=True,
            font_size=14,
            size_hint_y=None,
            halign="left",
            valign="top",
            color=(0, 1, 0, 1)
        )
        self.output_label.bind(texture_size=self.update_output_height)
        self.output_label.text_size = (self.scroll.width, None)
        self.scroll.add_widget(self.output_label)
        self.add_widget(self.scroll)

        # Command input
        self.command_input = TextInput(
            hint_text="Type command...",
            multiline=False,
            size_hint=(1, 0.1),
            foreground_color=(0, 1, 0, 1),
            background_color=(0, 0, 0, 1),
            cursor_color=(0, 1, 0, 1),
            padding=[10, 10, 10, 10]
        )
        self.command_input.bind(on_text_validate=self.run_command)
        self.add_widget(self.command_input)

        self.username = "user"
        self.hostname = "device"

    def update_output_height(self, instance, size):
        self.output_label.height = size[1]
        self.output_label.text_size = (self.output_label.width, None)
        Clock.schedule_once(lambda dt: setattr(self.scroll, 'scroll_y', 0))

    def run_command(self, instance):
        cmd = self.command_input.text.strip()
        prompt = f"[color=00ff00]{self.username}@{self.hostname}[/color]:~$ "

        if cmd:
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                output = result.stdout + result.stderr
                if not output.strip():
                    output = "(no output)"
            except Exception as e:
                output = f"[color=ff0000]Error:[/color] {str(e)}"

            self.output_text += f"\n{prompt}{cmd}\n{output}"
            self.output_label.text = self.output_text

        self.command_input.text = ''


class MainLayout(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(orientation='vertical', **kwargs)

        self.toggle_btn = Button(
            text="Open Terminal",
            size_hint=(1, 0.1),
            background_color=(0.2, 0.2, 0.2, 1),
            color=(1, 1, 1, 1)
        )
        self.toggle_btn.bind(on_press=self.toggle_terminal)

        self.terminal = Terminal()
        self.terminal.visible = False

        self.add_widget(self.toggle_btn)

    def toggle_terminal(self, instance):
        if self.terminal.parent is None:
            self.add_widget(self.terminal)
            self.toggle_btn.text = "Close Terminal"
        else:
            self.remove_widget(self.terminal)
            self.toggle_btn.text = "Open Terminal"


class TerminalApp(App):
    def build(self):
        return MainLayout()


if __name__ == '__main__':
    TerminalApp().run()
