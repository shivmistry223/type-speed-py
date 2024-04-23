import tkinter as tk
import time
import random
from tkinter import messagebox
import threading
from pymongo import MongoClient
import matplotlib.pyplot as plt
import bcrypt

# mongo URI
mongo_uri = "mongodb://localhost:27017/"


class LoginForm(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Login Form")
        self.geometry("300x350")

        self.heading_label = tk.Label(self,
                                      text="Typing Speed Test",
                                      font=("Arial", 24, "bold"),
                                      fg="#000000",
                                      padx=20,
                                      pady=10,)
        self.heading_label.pack()

        self.username_label = tk.Label(self,
                                       text="Username:",
                                       font=("Arial", 14),
                                       fg="#000000",
                                       padx=10,
                                       pady=5)
        self.username_label.pack()

        self.username_entry = tk.Entry(self,
                                       font=("Arial", 14),
                                       bg="#f2f2f2",
                                       fg="#000000",
                                       bd=2)
        self.username_entry.pack()

        self.password_label = tk.Label(self,
                                       text="Password:",
                                       font=("Arial", 14),
                                      fg="#000000",
                                       padx=10,
                                       pady=5)
        self.password_label.pack()

        self.password_entry = tk.Entry(self,
                                       font=("Arial", 14),
                                       bg="#f2f2f2",
                                       fg="#000000",
                                       bd=2,
                                       show="*")
        self.password_entry.pack()

        self.login_button = tk.Button(self,
                                      text="Login",
                                      font=("Arial", 14, "bold"),
                                      bg="#00b300",
                                      fg="#ffffff",
                                      activebackground="#008000",
                                      command=self.login)
        self.login_button.pack(pady=20)

        self.reg_button = tk.Button(self,
                                    text="Registration",
                                    font=("Arial", 14),
                                    bg="#00b300",
                                    fg="#ffffff",
                                    activebackground="#008000",
                                    command=self.registration)
        self.reg_button.pack()


        self.init_db()
        self.get_sample_text()
       
    def init_db(self):
        client = MongoClient(mongo_uri)
        db = client["typing_speed_db"]
        self.users = db["users"]
        self.sample_texts_db = db["test_example"]

    def get_sample_text(self):
        text_examples = self.sample_texts_db.find({})
        self.sample_texts = []
        for i in list(text_examples):
            # print(i['sample_text'])
            self.sample_texts.append(i['sample_text'])

    def hash_password(self, password):
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed_password

    def verify_password(self, hashed_password, input_password):
        return bcrypt.checkpw(input_password.encode('utf-8'), hashed_password)

    def registration(self):
        username = self.username_entry.get().strip()  
        password = self.password_entry.get()

      
        if not username or not password:
            messagebox.showerror("Error", "Please fill out both fields.")
            return
        if len(password) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters long.")
            return

      
        if self.users.find_one({"username": username}):
            messagebox.showerror("Error", "Username already exists.")
        else:
           
            self.users.insert_one({"username": username, "password": self.hash_password(password)})
            messagebox.showinfo("Success", "User registered successfully.\nYou can now login")
            self.password_entry.delete(0, tk.END)
            self.username_entry.delete(0, tk.END)


    def login(self):
        username = self.username_entry.get().strip()  
        password = self.password_entry.get()

      
        if not username or not password:
            messagebox.showerror("Error", "Please fill out both fields.")
            return

        user = self.users.find_one({"username": username})

        if user and self.verify_password(user["password"], password):
            messagebox.showinfo("Success", f"Welcome, {username}!")
            self.new_window = tk.Toplevel(self)
            self.new_window.title("Typing Speed Test")
            self.new_window.geometry("800x600")
            self.new_window.configure(bg="#f0f0f0")
            self.running = False
            self.counter = 0
            self.cps = 0
            self.cpm = 0

            self.create_widgets()
            self.get_sample_text()

        else:
            messagebox.showerror("Error", "Invalid username or password.")

    
    def save_result(self, username, wpm, accuracy):
        client = MongoClient(mongo_uri)
        db = client["typing_speed_db"]
        collection = db["test_results"]

        record = {
            "username": username,
            "wpm": wpm,
            "cps": accuracy,
            "timestamp": time.time()
        }
        collection.insert_one(record)

    
    def create_widgets(self):
        
        self.heading_label = tk.Label(self.new_window,
                                      text="Typing Speed Test",
                                      font=("Arial", 24, "bold"),
                                      fg="#000000",
                                      padx=20,
                                      pady=10,)
        self.heading_label.pack()

        self.button_frame = tk.Frame(self.new_window, bg="#f0f0f0") 
        self.button_frame.pack(pady=20)  

        self.start_button = tk.Button(self.button_frame, text="Start Test", command=self.start_test, font=("Arial", 14),
                                    bg="#4CAF50", fg="white")
        self.start_button.pack(side=tk.LEFT, padx=10) 

        self.reset_button = tk.Button(self.button_frame, text="Reset", command=self.reset, font=("Arial", 14),bg="#4CAF50", fg="white")
        self.reset_button.pack(side=tk.LEFT, padx=10)

        self.view_results_button = tk.Button(self.button_frame, text="View Test Results", command=self.view_test_results, font=("Arial", 14),
                                            bg="#4CAF50", fg="white")
        self.view_results_button.pack(side=tk.LEFT, padx=10)  

        self.logout_button = tk.Button(self.button_frame, text="Log Out", command=self.logout, font=("Arial", 14),
                                            bg="#4CAF50", fg="white")
        self.logout_button.pack(side=tk.LEFT, padx=10)  

        self.text_label = tk.Label(self.new_window, text="", wraplength=700, font=("Arial", 16), bg="#f0f0f0")
        self.text_label.pack(pady=20)

        self.input_text = tk.Text(self.new_window, width=80, font=("Arial", 12))
        self.input_text.pack(pady=20)
        self.input_text.config(state=tk.DISABLED)
        self.input_text.bind("<KeyPress>", self.start_time)

        self.result_label = tk.Label(self.new_window, text="Speed : \n0.00 CPS\n0.00 CPM", font=("Arial", 14), bg="#f0f0f0")
        self.result_label.pack(pady=20)

        
        
    def fetch_test_results(self, username):
        client = MongoClient(mongo_uri)
        db = client["typing_speed_db"]
        collection = db["test_results"]
        
        results = collection.find({"username": username}).sort("timestamp", 1)  # Sort by timestamp ascending
        
        timestamps = []
        wpms = []
        accuracies = []
        
        for result in results:
            timestamps.append(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(result["timestamp"])))
            wpms.append(result["wpm"])
            accuracies.append(result["cps"])
        
        return timestamps, wpms, accuracies

    def view_test_results(self):
        username = self.username_entry.get() 
        timestamps, wpms, accuracies = self.fetch_test_results(username) 
        
        if timestamps: 
            plt.figure(figsize=(10, 6))
            plt.plot(timestamps, wpms, marker='o', linestyle='-', color='b')
            plt.title("WPM Over Time")
            plt.xlabel("Test Date")
            plt.ylabel("Words Per Minute (WPM)")
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.show()
        else:
            messagebox.showinfo("No Data", "No test results found for this user.")

    def logout(self):
        if messagebox.askquestion("logout","Are you sure?"):

            self.destroy()

    def start_test(self):
        self.sample_text = random.choice(self.sample_texts)
        self.text_label.config(text=self.sample_text)
        self.input_text.config(state=tk.NORMAL)
        self.input_text.delete("1.0", tk.END)
        self.input_text.focus()

    def start_time(self, event):
        if not self.running:
            self.running = True
            t = threading.Thread(target=self.time_thread)
            t.start()
            
        if not self.text_label.cget('text').startswith(self.input_text.get("1.0",'end-1c')):
            self.input_text.config(fg="red")
        else:
            self.input_text.config(fg="black")

        if self.input_text.get("1.0",'end-1c') == self.text_label.cget('text')[:-1]:
            self.running = False
            self.input_text.config(fg="green")
            self.save_result(self.username_entry.get(), self.cpm, self.cps)

    def time_thread(self):
        while self.running:
            time.sleep(0.1)
            self.counter += 0.1
            self.cps = len(self.input_text.get("1.0",'end-1c')) / self.counter
            self.cpm = self.cps * 60

            self.result_label.config(text=f"Speed: {self.cps:.2f} CPS\n {self.cpm:.2f} CPM", bg="#f0f0f0")

    def reset(self):
        self.running = False
        self.counter = 0
        self.result_label.config(text=f"Speed: 0.00 CPS\n 0.00 CPM", bg="#f0f0f0")
        self.sample_text = random.choice(self.sample_texts)
        self.text_label.config(text=self.sample_text)
        self.input_text.config(state=tk.NORMAL)
        self.input_text.delete("1.0", tk.END)
        self.input_text.focus()


login_form = LoginForm()
login_form.mainloop()