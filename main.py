import sqlite3
import threading
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.scrollview import ScrollView
from kivy.uix.gridlayout import GridLayout
from kivy.core.window import Window
from kivy.uix.widget import Widget
from kivy.graphics import Color, RoundedRectangle

from GhostTrigger.PhantomGate import apiMain

t = threading.Thread(target=apiMain,args=())
t.start()

# Only for PC testing
Window.size = (360, 640)


class MyDatabase:
    def __init__(self, db_name='people.db'):
        self.conn = sqlite3.connect(db_name)
        self.create_table()

    def create_table(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS people (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL
            )
        ''')
        self.conn.commit()

    def add_person(self, name):
        cursor = self.conn.cursor()
        cursor.execute('INSERT INTO people (name) VALUES (?)', (name,))
        self.conn.commit()

    def get_all_people(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT id, name FROM people')
        return cursor.fetchall()

    def delete_person(self, person_id):
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM people WHERE id = ?', (person_id,))
        self.conn.commit()


class Card(BoxLayout):
    def __init__(self, **kwargs):
        super(Card, self).__init__(**kwargs)
        self.orientation = 'horizontal'
        self.padding = 10
        self.spacing = 10
        self.size_hint_y = None
        self.height = 60
        with self.canvas.before:
            Color(1, 1, 1, 1)  # White background
            self.bg = RoundedRectangle(radius=[10], pos=self.pos, size=self.size)
        self.bind(pos=self.update_bg, size=self.update_bg)

    def update_bg(self, *args):
        self.bg.pos = self.pos
        self.bg.size = self.size


class MobileUI(BoxLayout):
    def __init__(self, **kwargs):
        super(MobileUI, self).__init__(**kwargs)
        self.orientation = 'vertical'
        self.spacing = 10
        self.padding = 10
        self.db = MyDatabase()

        # Header
        header = Label(text="📱 My SQLite App", font_size=24, size_hint_y=None, height=50, bold=True)
        self.add_widget(header)

        # Input section
        self.input_card = BoxLayout(orientation='horizontal', size_hint_y=None, height=50, spacing=10)
        self.input_name = TextInput(hint_text='Enter name', multiline=False)
        self.add_button = Button(text='Add', size_hint_x=None, width=80)
        self.add_button.bind(on_press=self.add_name)
        self.input_card.add_widget(self.input_name)
        self.input_card.add_widget(self.add_button)
        self.add_widget(self.input_card)

        # Scrollable name list
        self.scroll = ScrollView()
        self.names_layout = GridLayout(cols=1, spacing=8, size_hint_y=None, padding=[0, 5])
        self.names_layout.bind(minimum_height=self.names_layout.setter('height'))
        self.scroll.add_widget(self.names_layout)
        self.add_widget(self.scroll)

        self.update_name_list()

    def add_name(self, instance):
        name = self.input_name.text.strip()
        if name:
            self.db.add_person(name)
            self.input_name.text = ''
            self.update_name_list()

    def delete_name(self, person_id):
        self.db.delete_person(person_id)
        self.update_name_list()

    def update_name_list(self):
        self.names_layout.clear_widgets()
        people = self.db.get_all_people()
        for person_id, name in people:
            name_card = Card()
            name_label = Label(text=name, font_size=18, color=(0, 0, 0, 1), halign='left', valign='middle')
            delete_button = Button(text='Delete', size_hint_x=None, width=80)
            delete_button.bind(on_press=lambda btn, pid=person_id: self.delete_name(pid))

            name_card.add_widget(name_label)
            name_card.add_widget(delete_button)
            self.names_layout.add_widget(name_card)


class MyApp(App):
    def build(self):
        return MobileUI()


if __name__ == '__main__':
    MyApp().run()
