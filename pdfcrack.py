import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import pikepdf
import string
import itertools
import random
import time
from tqdm import tqdm
import webbrowser


class PDFCrackerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PDF Password Cracker")
        self.root.geometry("660x280")  # Adjust the window size
        self.numbers_checked = tk.BooleanVar()
        self.special_chars_checked = tk.BooleanVar()
        self.letters_checked = tk.BooleanVar()
        # Create toolbar frame

        # Add donate button to toolbar
        self.donate_button = tk.Button(root, text="Donate", command=self.open_donation_link)
        self.donate_button.grid(row=0, column=6, padx=2, pady=2)

        # PDF File
        self.pdf_file_label = tk.Label(root, text="PDF File:")
        self.pdf_file_label.grid(row=0, column=0, sticky=tk.W)
        self.pdf_file_entry = tk.Entry(root, width=25)
        self.pdf_file_entry.grid(row=0, column=1, columnspan=3)
        self.pdf_file_entry.bind("<KeyRelease>", self.validate_wordlist_entry)
        self.pdf_file_button = tk.Button(root, text="Browse", command=self.browse_pdf_file)
        self.pdf_file_button.grid(row=0, column=4)

        # Divider1
        self.divider1 = tk.Canvas(root, width=660, height=2, bg="gray")
        self.divider1.grid(row=1, column=0, columnspan=7, sticky="ew")

        # Wordlist input
        self.wordlist_label = tk.Label(root, text="Wordlist:")
        self.wordlist_label.grid(row=2, column=0, sticky=tk.W)
        self.wordlist_entry = tk.Entry(root, width=25)
        self.wordlist_entry.grid(row=2, column=1, columnspan=3)
        self.wordlist_entry.bind("<KeyRelease>", self.validate_wordlist_entry)
        self.wordlist_button = tk.Button(root, text="Browse", command=self.browse_wordlist)
        self.wordlist_button.grid(row=2, column=4)  # This line was missing

        # Crack PDF (Wordlist) section
        self.wordlist_display = tk.Label(root, text="Wordlist Crack:")
        self.wordlist_display.grid(row=3, column=0, sticky=tk.W)
        self.wordlist_status = tk.Label(root, text="")
        self.wordlist_status.grid(row=4, column=0, columnspan=4, sticky=tk.W)
        self.wordlist_start_button = tk.Button(root, text="Start", command=self.start_wordlist_crack, state=tk.DISABLED)
        self.wordlist_start_button.grid(row=4, column=5)
        self.wordlist_stop_button = tk.Button(root, text="Stop", command=self.stop_wordlist_crack, state=tk.DISABLED)
        self.wordlist_stop_button.grid(row=4, column=6)

        # Divider2
        self.divider2 = tk.Canvas(root, width=660, height=2, bg="gray")
        self.divider2.grid(row=5, column=0, columnspan=7, sticky="ew")

        # Crack PDF (Incremental) section
        self.incremental_display = tk.Label(root, text="Incremental Crack:")
        self.incremental_display.grid(row=6, column=0, sticky=tk.W)
        self.incremental_status = tk.Label(root, text="")
        self.incremental_status.grid(row=7, column=0, columnspan=4, sticky=tk.W)

        # Checkboxes for character sets
        self.numbers_checkbox = tk.Checkbutton(root, text="Numbers", variable=self.numbers_checked, command=self.update_incremental_charset)
        self.numbers_checkbox.grid(row=6, column=4, sticky=tk.W)
        self.special_chars_checkbox = tk.Checkbutton(root, text="Special Characters", variable=self.special_chars_checked,
                                                     command=self.update_incremental_charset)
        self.special_chars_checkbox.grid(row=6, column=5, sticky=tk.W)
        self.letters_checkbox = tk.Checkbutton(root, text="Letters",variable=self.letters_checked, command=self.update_incremental_charset)
        self.letters_checkbox.grid(row=6, column=6, sticky=tk.W)
        self.letters_checkbox.select()  # Default to including letters

        self.incremental_start_button = tk.Button(root, text="Start", command=self.start_incremental_crack,
                                                  state=tk.DISABLED)
        self.incremental_start_button.grid(row=7, column=5)
        self.incremental_stop_button = tk.Button(root, text="Stop", command=self.stop_incremental_crack,
                                                 state=tk.DISABLED)
        self.incremental_stop_button.grid(row=7, column=6)

        # Divider3
        self.divider3 = tk.Canvas(root, width=660, height=2, bg="gray")
        self.divider3.grid(row=8, column=0, columnspan=7, sticky="ew")

        # Random password length
        self.random_display = tk.Label(root, text="Random Crack:")
        self.random_display.grid(row=9, column=0, sticky=tk.W)
        self.min_length_label = tk.Label(root, text="Min Length:")
        self.min_length_label.grid(row=9, column=1, sticky=tk.W)
        self.min_length_entry = tk.Entry(root, width=5)
        self.min_length_entry.grid(row=9, column=2)
        self.min_length_entry.bind("<KeyRelease>", self.validate_min_length_entry)  # Bind validation method
        self.max_length_label = tk.Label(root, text="Max Length:")
        self.max_length_label.grid(row=9, column=3, sticky=tk.W)
        self.max_length_entry = tk.Entry(root, width=5)
        self.max_length_entry.grid(row=9, column=4)
        self.max_length_entry.bind("<KeyRelease>", self.validate_max_length_entry)  # Bind validation method
        self.random_start_button = tk.Button(root, text="Start", command=self.start_random_crack, state=tk.DISABLED)
        self.random_start_button.grid(row=9, column=5)
        self.random_stop_button = tk.Button(root, text="Stop", command=self.stop_random_crack, state=tk.DISABLED)
        self.random_stop_button.grid(row=9, column=6)

        # Random Status
        self.random_status = tk.Label(root, text="")
        self.random_status.grid(row=10, column=0, columnspan=7, sticky=tk.W)

        # Display found password
        self.found_password_label = tk.Label(root, text="Found Password:")
        self.found_password_label.grid(row=11, column=0, sticky=tk.W)
        self.found_password_display = tk.Entry(root, width=50, state=tk.DISABLED)
        self.found_password_display.grid(row=11, column=1, columnspan=6)

        # Variables to control thread states
        self.wordlist_stop_event = threading.Event()
        self.incremental_stop_event = threading.Event()
        self.random_stop_event = threading.Event()
        self.password_found = threading.Event()

    def open_donation_link(self):
        webbrowser.open("https://www.paypal.com/donate/?hosted_button_id=J2ECNB3W3KG6C")

    def validate_wordlist_entry(self, event=None):
        print("validating")
        pdf_file_filled = bool(self.pdf_file_entry.get())
        wordlist_filled = bool(self.wordlist_entry.get())

        if pdf_file_filled and wordlist_filled:
            self.wordlist_start_button.config(state=tk.NORMAL)
            self.wordlist_stop_button.config(state=tk.DISABLED)
        else:
            self.wordlist_start_button.config(state=tk.DISABLED)
            if wordlist_filled:
                self.wordlist_stop_button.config(state=tk.DISABLED)
            else:
                self.wordlist_stop_button.config(state=tk.DISABLED)

    def update_incremental_charset(self):
        charset = ''
        if self.numbers_checked.get():
            charset += string.digits
        if self.special_chars_checked.get():
            charset += "!@#$%^&*()"
        if self.letters_checked.get():
            charset += string.ascii_letters
        self.incremental_charset = charset

    def validate_min_length_entry(self, event):
        if self.pdf_file_entry.get() and self.min_length_entry.get() and self.max_length_entry.get():
            self.random_start_button.config(state=tk.NORMAL)
            self.random_stop_button.config(state=tk.DISABLED)
        else:
            self.random_start_button.config(state=tk.DISABLED)
            self.random_stop_button.config(state=tk.DISABLED)

    def validate_max_length_entry(self, event):
        if self.pdf_file_entry.get() and self.min_length_entry.get() and self.max_length_entry.get():
            self.random_start_button.config(state=tk.NORMAL)
            self.random_stop_button.config(state=tk.DISABLED)
        else:
            self.random_start_button.config(state=tk.DISABLED)
            self.random_stop_button.config(state=tk.DISABLED)

    def browse_pdf_file(self):
        filename = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
        self.pdf_file_entry.delete(0, tk.END)
        self.pdf_file_entry.insert(tk.END, filename)
        self.enable_incremental_start()
        self.validate_wordlist_entry()

    def enable_incremental_start(self):
        if self.pdf_file_entry.get():
            self.incremental_start_button.config(state=tk.NORMAL)

    def browse_wordlist(self):
        filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        self.wordlist_entry.delete(0, tk.END)
        self.wordlist_entry.insert(tk.END, filename)
        self.validate_wordlist_entry()

    def start_wordlist_crack(self):
        self.wordlist_start_button.config(state=tk.DISABLED)
        self.wordlist_stop_button.config(state=tk.NORMAL)
        self.wordlist_stop_event.clear()
        pdf_file = self.pdf_file_entry.get()
        wordlist = self.wordlist_entry.get()
        if pdf_file and wordlist:
            self.wordlist_thread = threading.Thread(target=self.crack_pdf_with_wordlist, args=(pdf_file, wordlist))
            self.wordlist_thread.start()
        else:
            messagebox.showerror("Error", "Please select PDF file and wordlist.")

    def start_incremental_crack(self):
        self.incremental_start_button.config(state=tk.DISABLED)
        self.incremental_stop_button.config(state=tk.NORMAL)
        self.incremental_stop_event.clear()
        pdf_file = self.pdf_file_entry.get()
        if pdf_file:
            self.update_incremental_charset()
            self.incremental_thread = threading.Thread(target=self.crack_pdf_incremental, args=(pdf_file,))
            self.incremental_thread.start()
        else:
            messagebox.showerror("Error", "Please select PDF file.")

    def start_random_crack(self):
        self.random_start_button.config(state=tk.DISABLED)
        self.random_stop_button.config(state=tk.NORMAL)
        self.random_stop_event.clear()
        pdf_file = self.pdf_file_entry.get()
        min_length = self.min_length_entry.get()
        max_length = self.max_length_entry.get()
        if pdf_file and min_length and max_length:
            self.random_thread = threading.Thread(target=self.crack_pdf_random,
                                                  args=(pdf_file, int(min_length), int(max_length)))
            self.random_thread.start()
        else:
            messagebox.showerror("Error", "Please select PDF file and specify min/max length.")

    def stop_wordlist_crack(self):
        self.wordlist_stop_event.set()
        if not self.password_found.is_set():  # Check if password not found
            self.incremental_stop_event.set()  # Stop incremental crack
            self.random_stop_event.set()  # Stop random crack
        self.wordlist_start_button.config(state=tk.NORMAL)
        self.wordlist_stop_button.config(state=tk.DISABLED)

    def stop_incremental_crack(self):
        self.incremental_stop_event.set()
        if not self.password_found.is_set():  # Check if password not found
            self.wordlist_stop_event.set()  # Stop wordlist crack
            self.random_stop_event.set()  # Stop random crack
        self.incremental_start_button.config(state=tk.NORMAL)
        self.incremental_stop_button.config(state=tk.DISABLED)

    def stop_random_crack(self):
        self.random_stop_event.set()
        if not self.password_found.is_set():  # Check if password not found
            self.wordlist_stop_event.set()  # Stop wordlist crack
            self.incremental_stop_event.set()  # Stop incremental crack
        self.random_start_button.config(state=tk.NORMAL)
        self.random_stop_button.config(state=tk.DISABLED)

    def crack_pdf_with_wordlist(self, pdf_file, wordlist):
        self.wordlist_status.config(text="Cracking...")
        start_time = time.time()
        with open(wordlist, 'r') as f:
            passwords = [line.strip() for line in f]

        for password in tqdm(passwords, "Wordlist Crack"):
            if self.wordlist_stop_event.is_set():
                break
            try:
                with pikepdf.open(pdf_file, password=password) as pdf:
                    end_time = time.time()
                    elapsed_time = end_time - start_time
                    self.found_password_display.config(state=tk.NORMAL)
                    self.found_password_display.delete(0, tk.END)
                    self.found_password_display.insert(tk.END, password)
                    self.found_password_display.config(state=tk.DISABLED)
                    self.wordlist_status.config(
                        text=f"Password found: {password} (Time taken: {elapsed_time:.2f} seconds)")
                    self.password_found.set()
                    print("found")
                    return
            except pikepdf.PasswordError:
                self.wordlist_status.config(text=f"Trying password: {password}")

    def crack_pdf_incremental(self, pdf_file):
        self.incremental_status.config(text="Cracking...")
        start_time = time.time()
        for password_length in range(1, 9):
            if self.incremental_stop_event.is_set():  # Check if stop event is set
                break
            for combination in itertools.product(self.incremental_charset, repeat=password_length):
                if self.incremental_stop_event.is_set():  # Check if stop event is set
                    break
                password = ''.join(combination)
                try:
                    with pikepdf.open(pdf_file, password=password) as pdf:
                        end_time = time.time()
                        elapsed_time = end_time - start_time
                        self.found_password_display.config(state=tk.NORMAL)
                        self.found_password_display.delete(0, tk.END)
                        self.found_password_display.insert(tk.END, password)
                        self.found_password_display.config(state=tk.DISABLED)
                        self.incremental_status.config(
                            text=f"Password found: {password} (Time taken: {elapsed_time:.2f} seconds)")
                        self.password_found.set()
                        print("found in")
                        return
                except pikepdf.PasswordError:
                    self.incremental_status.config(text=f"Trying password: {password}")

    def crack_pdf_random(self, pdf_file, min_length, max_length):
        self.random_status.config(text="Cracking...")
        start_time = time.time()
        while True:
            if self.random_stop_event.is_set():
                break
            password = self.generate_password(random.randint(min_length, max_length))
            try:
                with pikepdf.open(pdf_file, password=password) as pdf:
                    end_time = time.time()
                    elapsed_time = end_time - start_time
                    self.found_password_display.config(state=tk.NORMAL)
                    self.found_password_display.delete(0, tk.END)
                    self.found_password_display.insert(tk.END, password)
                    self.found_password_display.config(state=tk.DISABLED)
                    self.random_status.config(
                        text=f"Password found: {password} (Time taken: {elapsed_time:.2f} seconds)")
                    self.password_found.set()
                    return
            except pikepdf.PasswordError:
                self.random_status.config(text=f"Trying password: {password}")

    def generate_password(self, length):
        """Generate a random password of given length"""
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))


if __name__ == "__main__":
    root = tk.Tk()
    app = PDFCrackerGUI(root)
    root.mainloop()
