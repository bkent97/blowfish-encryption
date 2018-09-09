from kivy.app import App
from kivy.uix.floatlayout import FloatLayout
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.uix.popup import Popup
from kivy.uix.textinput import TextInput
import blowfish

import os

en_key = b''
conf_file = ""
records = []
try:
     f = open("records.txt", "r")
     lines = f.read().splitlines()
     for line in lines:
          records.append(line)

except:
     print("'records.txt' not found")

class KeyDialog(FloatLayout):
    cancel = ObjectProperty(None)
    change_color = ObjectProperty(None)

class ConfirmationEDialog(FloatLayout):
    confirm_encrypt = ObjectProperty(None)
    cancel = ObjectProperty(None)

class ConfirmationDDialog(FloatLayout):
    confirm_decrypt = ObjectProperty(None)
    cancel = ObjectProperty(None)

class EncryptDialog(FloatLayout):
    encrypt = ObjectProperty(None)
    cancel = ObjectProperty(None)

class DecryptDialog(FloatLayout):
    decrypt = ObjectProperty(None)
  #  text_input = ObjectProperty(None)
    cancel = ObjectProperty(None)

class Root(FloatLayout):
    encryptfile = ObjectProperty(None)
    decryptfile = ObjectProperty(None)
#    text_input = TextInput(text='')
 
    def update_key(self, key):
        global en_key
        en_key = bytes(key, encoding='utf-8')

    def dismiss_popup(self):
        self._popup.dismiss()

    def show_encrypt(self):
        if len(en_key) < 4 or len(en_key) > 56:
            content = KeyDialog(cancel=self.dismiss_popup)
            self._popup = Popup(title="Invalid Key", content=content,
                            size_hint=(0.3, 0.3))
            self._popup.open()
            return

        content = EncryptDialog(encrypt=self.encrypt, cancel=self.dismiss_popup)
        self._popup = Popup(title="Encrypt file", content=content,
                            size_hint=(0.9, 0.9))
        self._popup.open()

    def show_decrypt(self):
        if len(en_key) < 4 or len(en_key) > 56:
            content = KeyDialog(cancel=self.dismiss_popup)
            self._popup = Popup(title="Invalid Key", content=content,
                            size_hint=(0.3, 0.3))
            self._popup.open()
            return

        content = DecryptDialog(decrypt=self.decrypt, cancel=self.dismiss_popup)
        self._popup = Popup(title="Decrypt file", content=content,
                            size_hint=(0.9, 0.9))
        self._popup.open()

       
    def confirm_encrypt(self):
        global conf_file
        records.remove(conf_file)
        w = open('records.txt', "w")
        for record in records:
             w.write(record)

        conf_file = ""
        self.dismiss_popup()

    def encrypt(self, path, filename):
        filepath = os.path.join(path, filename[0])
        if filepath in records:
             self.dismiss_popup()
             global conf_file
             conf_file = filepath
             content = ConfirmationEDialog(confirm_encrypt=self.confirm_encrypt, cancel=self.dismiss_popup)
             self._popup = Popup(title="Warning", content=content,
                            size_hint=(0.5, 0.5))
             self._popup.open()
             return
        
        f = open(filepath, "rb")
        data = f.read()
        f.close()

        cipher = blowfish.Cipher(en_key)
        data_encrypted = b"".join(cipher.encrypt_ecb_cts(data))

        w = open(filepath, "wb")
        w.write(data_encrypted)
        w.close()

        records.append(filepath)
        r = open('records.txt', "w")
        for record in records:
             r.write(record)

        r.close()

        self.dismiss_popup()

   
    def confirm_decrypt(self):
        global conf_file
        records.append(conf_file)
        w = open('records.txt', "w")
        for record in records:
             w.write(record)

        conf_file = ""
        self.dismiss_popup()


    def decrypt(self, path, filename):
        filepath = os.path.join(path, filename[0])
        if filepath not in records:
             self.dismiss_popup()
             global conf_file
             conf_file = filepath
             content = ConfirmationDDialog(confirm_decrypt=self.confirm_decrypt, cancel=self.dismiss_popup)
             self._popup = Popup(title="Warning", content=content,
                            size_hint=(0.5, 0.5))
             self._popup.open()
             return

        f = open(os.path.join(path, filename[0]), "rb")
        data = f.read()
        f.close()

        cipher = blowfish.Cipher(en_key)
        data_decrypted = b"".join(cipher.decrypt_ecb_cts(data))
        
        w = open(os.path.join(path, filename[0]), "wb")
        w.write(data_decrypted)
        w.close()

        records.remove(filepath)
        r = open('records.txt', "w")
        for record in records:
             r.write(record)

        r.close()

        self.dismiss_popup()


class Editor(App):
    pass


Factory.register('Root', cls=Root)
Factory.register('EncryptDialog', cls=EncryptDialog)
Factory.register('DecryptDialog', cls=DecryptDialog)
Factory.register('KeyDialog', cls=KeyDialog)
Factory.register('ConfirmationDDialog', cls=ConfirmationDDialog)
Factory.register('ConfirmationEDialog', cls=ConfirmationEDialog)


if __name__ == '__main__':
    Editor().run()
