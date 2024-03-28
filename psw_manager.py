import base64
import hashlib
import hmac
import json
import os
import re
import tkinter as tk
from json import JSONEncoder
from tkinter import DISABLED, NORMAL, END
from tkinter import messagebox

ACCOUNTS = "accounts.json"

def close_windows(first, second):
    first.destroy()
    second.destroy()
    
accounts = {}

user = None

"""
class to support to save dict to file
"""

class CustomEncoder(JSONEncoder):
    def default(self, o):
        return o.__dict__

class Account:
    def __init__(self, d, username='', password='', website_name='', website_url=''):

        if d:  
            for key, value in d.items():
                setattr(self, key, value)
        else:
            self.username = username

            # create security password with hash and salt
            self.salt_pass = os.urandom(16)
            self.pw_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), self.salt_pass, 100000)

            # store string
            self.salt_pass = base64.b64encode(self.salt_pass).decode('ascii')
            self.pw_hash = base64.b64encode(self.pw_hash).decode('ascii')

            self.website_name = website_name
            self.website_url = website_url

    """
    check if user enter valid pass
    """

    def check_pass(self, password):
        return hmac.compare_digest(
            base64.b64decode(self.pw_hash),
            hashlib.pbkdf2_hmac('sha256', password.encode(), base64.b64decode(self.salt_pass), 100000)
        )

"""
validate the password strength
"""

def validate_password(password):
    # at least 8 characters
    if len(password) < 8:
        return False

    # at least one uppercase letter
    if not re.search(r'[A-Z]', password):
        return False

    # at least one lowercase letter
    if not re.search(r'[a-z]', password):
        return False

    # contains at least one digit
    if not re.search(r'\d', password):
        return False

    # contains at least one special character
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False

    # the password is valid
    return True


def save_accounts():
    with open(ACCOUNTS, 'w') as f:
        f.write(json.dumps(accounts, cls=CustomEncoder))

def load_accounts():
    accounts = {}
    try:
        with open(ACCOUNTS) as f:
            json_data = json.loads(f.read())
            for key, value in json_data.items():
                accounts[key] = Account(value)
    except:
        pass
    return accounts


"""
display welcome screen and allow user to choose login, register,
manage the account and exit the program
"""

class MainClass:
    def __init__(self):
        self.root = tk.Tk()
        self.frame = tk.Frame(self.root)

        # set title
        self.root.title('Dictionary-based Password Manager')
        # set size and center screen
        self.root.geometry('400x400+50+50')

        self.frame.columnconfigure(0, weight=1)

        tk.Label(self.frame, text='Welcome to Dictionary-based Password Manager').grid(column=0, row=0, sticky=tk.W)

        # login button
        self.login_button = tk.Button(self.frame, text="Login", command=self.do_login)
        self.login_button.config(width=20, height=2)

        # register button
        self.register_button = tk.Button(self.frame, text="Register", command=self.do_register)
        self.register_button.config(width=20, height=2)

        # account button
        self.my_account_button = tk.Button(self.frame, text="My Account", command=self.do_my_account)
        self.my_account_button.config(width=20, height=2, state=DISABLED)

        # logout button
        self.logout_button = tk.Button(self.frame, text="Logout", command=self.do_logout)
        self.logout_button.config(width=20, height=2, state=DISABLED)

        # exit button
        self.exit_button = tk.Button(self.frame, text="Exit", command=self.do_exit)
        self.exit_button.config(width=20, height=2)

        # add padding x, y
        for widget in self.frame.winfo_children():
            widget.grid(padx=5, pady=5)

        self.frame.grid(column=0, row=0)

        self.frame.pack()

        self.root.mainloop()

    """
    close this window and open login screen
    """

    def do_login(self):
        LoginRegisterClass(self, True)

    """
        close this window and open register screen
    """

    def do_register(self):
        LoginRegisterClass(self, False)

    """
        close this window and open my account screen
        """

    def do_my_account(self):
        MyAccountScreen(self)

    """
        logout
    """

    def do_logout(self):
        global user
        user = None
        self.reload_window()

    """
    call when the logged in/ logout/ delete account successfully
    """

    def reload_window(self):
        global user
        if user is None:
            self.login_button.config(state=NORMAL)
            self.register_button.config(state=NORMAL)
            self.my_account_button.config(state=DISABLED)
            self.logout_button.config(state=DISABLED)
        else:
            self.login_button.config(state=DISABLED)
            self.register_button.config(state=DISABLED)
            self.my_account_button.config(state=NORMAL)
            self.logout_button.config(state=NORMAL)

    """
        exit the program
    """

    def do_exit(self):
        self.root.destroy()

"""
My Account class.
User can view, update, delete the account
"""

class MyAccountScreen:
    def __init__(self, previous_screen):

        global user

        previous_screen.root.withdraw()
        self.previous_screen = previous_screen
        self.root = tk.Tk()
        self.frame = tk.Frame(self.root)

        self.root.protocol("WM_DELETE_WINDOW", lambda: close_windows(previous_screen.root, self.root))

        # set title
        self.root.title('Dictionary-based Password Manager')
        # set size and center screen
        self.root.geometry('650x230+50+50')

        self.username = tk.StringVar(self.frame, value=user.username)
        self.website_name = tk.StringVar(self.frame, value=user.website_name)
        self.website_url = tk.StringVar(self.frame, value=user.website_url)

        tk.Label(self.frame, text='My Account').grid(column=0, row=0, sticky=tk.W)

        # Create and place the username label and entry
        username_label = tk.Label(self.frame, text="Username:")
        username_label.grid(column=0, row=1, sticky=tk.W)

        self.username_entry = tk.Entry(self.frame, textvariable=self.username)
        self.username_entry.grid(column=1, row=1, sticky=tk.W)
        self.username_entry.config(state=DISABLED)

        # Create and place the password label and entry
        password_label = tk.Label(self.frame, text="Password:")
        password_label.grid(column=0, row=2, sticky=tk.W)

        self.password_entry = tk.Entry(self.frame, show="*")  # Show asterisks for password
        self.password_entry.grid(column=1, row=2, sticky=tk.W)

        # Create and place the webiste name label and entry
        websitename_label = tk.Label(self.frame, text="Website Name:")
        websitename_label.grid(column=0, row=3, sticky=tk.W)

        self.websitename_entry = tk.Entry(self.frame, width=50, textvariable=self.website_name)
        self.websitename_entry.grid(column=1, row=3, sticky=tk.W)
        self.websitename_entry.insert(END, user.website_name)

        # Create and place the url label and entry
        websiteurl_label = tk.Label(self.frame, text="Website URL:")
        websiteurl_label.grid(column=0, row=4, sticky=tk.W)

        self.websiteurl_entry = tk.Entry(self.frame, width=50, textvariable=self.website_url)
        self.websiteurl_entry.grid(column=1, row=4, sticky=tk.W)
        self.websiteurl_entry.insert(END, user.website_url)

        # Update button
        update_button = tk.Button(self.frame, text='Update', command=self.do_update)
        update_button.config(width=20, height=2)
        update_button.grid(column=0, row=5, sticky=tk.W)

        # Delete button
        delete_button = tk.Button(self.frame, text='Delete', command=self.do_delete)
        delete_button.config(width=20, height=2)
        delete_button.grid(column=1, row=5, sticky=tk.W)

        # cancel button
        cancel_button = tk.Button(self.frame, text="Cancel", command=self.do_cancel)
        cancel_button.config(width=20, height=2)
        cancel_button.grid(column=2, row=5, sticky=tk.W)

        # add padding x, y
        for widget in self.frame.winfo_children():
            widget.grid(padx=5, pady=5)

        self.frame.grid(column=0, row=0)

        self.frame.pack()
        self.root.mainloop()

    """
        delete button handler
    """

    def do_delete(self):
        global user
        res = messagebox.askquestion('Confirmation', 'Do you really want to delete your account?')
        if res == 'yes':
            # delete the account
            del accounts[user.username]
            user = None
            save_accounts()

            messagebox.showinfo("Account",
                                "Account has been deleted successfully")

            self.previous_screen.reload_window()
            self.root.destroy()
            self.previous_screen.root.deiconify()  # show the welcome screen

    """
    update button handler
    """

    def do_update(self):

        global user
        global accounts

        password = self.password_entry.get()

        if password != "" and not validate_password(password):
            messagebox.showwarning("Invalid password",
                                   "Please enter password that has at least 8 characters, 1 lowercase, "
                                   "1 uppercase and 1 special character")
            return

        # update/save the account
        accounts[user.username].website_name = self.website_name.get()
        accounts[user.username].website_url = self.website_url.get()
        if password != "":
            user = Account(None, user.username, password, self.website_name.get(), self.website_url.get())
            accounts[user.username] = user
        else:
            user = accounts[user.username]

        save_accounts()

        messagebox.showinfo("Account",
                            "Account has been updated successfully")

        self.root.destroy()
        self.previous_screen.root.deiconify()  # show the welcome screen

    """
        close this window and open main screen
    """

    def do_cancel(self):
        self.root.destroy()
        self.previous_screen.root.deiconify()  # show the welcome screen


"""
Login or Register class
"""


class LoginRegisterClass:

    # constructor
    def __init__(self, previous_screen, is_login):

        previous_screen.root.withdraw()
        self.is_login = is_login
        self.previous_screen = previous_screen
        self.root = tk.Tk()
        self.frame = tk.Frame(self.root)

        self.root.protocol("WM_DELETE_WINDOW", lambda: close_windows(previous_screen.root, self.root))

        # set title
        self.root.title('Dictionary-based Password Manager')
        # set size and center screen
        self.root.geometry('600x200+50+50')

        self.frame.columnconfigure(0, weight=1)

        title = ""
        if is_login:
            title = 'Login Screen'
        else:
            title = "Register Screen"

        tk.Label(self.frame, text=title).grid(column=0, row=0, sticky=tk.W)

        # Create and place the username label and entry
        username_label = tk.Label(self.frame, text="Username:")
        username_label.grid(column=0, row=1, sticky=tk.W)

        self.username_entry = tk.Entry(self.frame)
        self.username_entry.grid(column=1, row=1, sticky=tk.W)

        # Create and place the password label and entry
        password_label = tk.Label(self.frame, text="Password:")
        password_label.grid(column=2, row=1, sticky=tk.W)

        self.password_entry = tk.Entry(self.frame, show="*")  # Show asterisks for password
        self.password_entry.grid(column=3, row=1, sticky=tk.W)

        # login/register button

        login_register_title = ""
        if is_login:
            login_register_title = 'Login'
        else:
            login_register_title = "Register"

        login_button = tk.Button(self.frame, text=login_register_title, command=self.do_login_register)
        login_button.config(width=20, height=2)
        login_button.grid(column=0, row=2, sticky=tk.W)

        # cancel button
        cancel_button = tk.Button(self.frame, text="Cancel", command=self.do_cancel)
        cancel_button.config(width=20, height=2)
        cancel_button.grid(column=1, row=2, sticky=tk.W)

        # add padding x, y
        for widget in self.frame.winfo_children():
            widget.grid(padx=5, pady=5)

        self.frame.grid(column=0, row=0)

        self.frame.pack()

        # Set the focus to Entry widget
        self.username_entry.after(1, lambda: self.username_entry.focus_force())
        self.root.mainloop()

    """
    process login or register
    """

    def do_login_register(self):
        done = False  # if login or register success
        global user

        username = self.username_entry.get()
        password = self.password_entry.get()

        if username == "" or password == "":
            messagebox.showwarning("Invalid input", "Please enter username, password")
            return

        if self.is_login:  # login screen
            if username not in accounts:
                messagebox.showwarning("Username",
                                       "Incorrect username")
                return
            else:
                account = accounts[username]
                if not account.check_pass(password):
                    messagebox.showwarning("Password",
                                           "Incorrect password")
                    return

                user = account
            self.previous_screen.reload_window()

            done = True
        else:  # register
            if not validate_password(password):
                messagebox.showwarning("Invalid password",
                                       "Please enter password that has at least 8 characters, 1 lowercase, "
                                       "1 uppercase and 1 special character")
                return
            else:
                if username in accounts:
                    messagebox.showwarning("Existing username",
                                           "Please enter another username")
                    return
                else:
                    accounts[username] = Account(None, username, password, "", "")
                    save_accounts()
                    done = True

        if done:  # close this window
            self.root.destroy()
            self.previous_screen.root.deiconify()  # show the welcome screen

    """
        close this window and open main screen
    """

    def do_cancel(self):
        self.root.destroy()
        self.previous_screen.root.deiconify()  # show the welcome screen


if __name__ == '__main__':
    accounts = load_accounts()  # load accounts
    MainClass()
