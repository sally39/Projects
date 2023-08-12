from tkinter import *
from tkinter import ttk
import tkinter as tk
import sqlite3
from contextlib import closing
from tkinter import PhotoImage


root2 = tk.Tk()
root2.withdraw()
root3 = tk.Tk()
root3.withdraw()


E1 = ttk.Entry(root2, width=25)
E2 = ttk.Entry(root2, width=25)
E3 = ttk.Entry(root2, width=25)
E4 = tk.Entry(root2, width=25)
E5 = tk.Entry(root2, width=25)
E6 = ttk.Entry(root2, width=25)
E7 = ttk.Entry(root2, width=25)
E8 = ttk.Entry(root3, width=25)
EE1 = ttk.Entry(root3, width=25)



file = "C:\\Users\\SALEHA\\bld_bank.db"

root1 = tk.Tk()
root1.title("BLOOD BANK MANAGEMENT SYSTEM")
root1.geometry("1000x1000")
frame = tk.Frame(root1, bg="red")

#tk.Label(root1,image=PhotoImage(file="C:\Users\SALEHA\OneDrive\Pict…
with closing(sqlite3.connect(file)) as conn:
    with closing(conn.cursor()) as c:
            try:
                c.execute("create table if not exists donar(d_Id integer,d_name varchar(20),d_age integer,d_contact_no integer,d_gender varchar(1),d_address varchar(20),d_blood_group varchar(5),PRIMARY KEY(d_Id));")
            except:
                print("db table creation ERROR")

            if E1.get() == '':
                did = E6.get()
                print(did)
            else:
                did = E1.get()
                print(did)

            query = "select * from donar where d_Id= d_Id;"
            c.execute(query)
            if len(c.fetchall()) == 0:
                print("record not found")
            else:
                print("record found")


def update():
    root2.deiconify()
    tk.Button(root2, text='search', command=search).grid(row=0, column=0)
    #E1=ttk.Entry(root2,width=25,textvariable=CID)
    E1.grid(row=0, column=1)

    tk.Label(root2, text="NAME").grid(row=1, column=0)
    #E2=ttk.Entry(root2,width=25,textvariable=NAME)
    E2.grid(row=1, column=1)

    tk.Label(root2, text="AGE").grid(row=2, column=0)
    #E3=ttk.Entry(root2,width=25,textvariable=AGE)
    E3.grid(row=2, column=1)

    tk.Label(root2, text="CONTACT_NO").grid(row=3, column=0)
    #E4=tk.Entry(root2,width=25,textvariable=CONTACT_NO)
    E4.grid(row=3, column=1)

    tk.Label(root2, text="GENDER").grid(row=4, column=0)
    #E5=tk.Entry(root2,width=25,textvariable=GENDER)
    E5.grid(row=4, column=1)

    tk.Label(root2, text="ADDRESS").grid(row=5, column=0)
    # E5=tk.Entry(root2,width=25,textvariable=ADDRESS)
    E6.grid(row=5, column=1)

    tk.Label(root2, text="BLOOD_GROUP").grid(row=6, column=0)
    # E5=tk.Entry(root2,width=25,textvariable=BLOOD_GROUP)
    E7.grid(row=6, column=1)

    tk.Button(root2, text='UPDATE', command=update2).grid(row=7, column=0)
    #E1.delete(0, "end")
    #E2.delete(0, "end")

    root2.mainloop()


def delete2():
    with closing(sqlite3.connect(file)) as conn:
        with closing(conn.cursor()) as c:
            try:
                c.execute("create table if not exists donar(d_Id integer,d_name varchar(20),d_age integer,d_contact_no integer,d_gender varchar(1),d_address varchar(20),d_blood_group varchar(5),PRIMARY KEY(d_Id));")
            except:
                print("db table creation ERROR")
            did = int(EE1.get())

            c.execute("delete from donar where d_Id =:did", {"did":did})
            conn.commit()
            print("record deleted")
            # root3.withdraw()


def delete():
    root3.deiconify()
    tk.Button(root3, text='search', command=search).grid(row=0, column=0)
    EE1.grid(row=0, column=1)

    tk.Button(root3, text='DELETE', command=delete2).grid(row=1, column=0)
    root3.mainloop()

def insert():
    root2.deiconify()

    tk.Label(root2, text="DID").grid(row=1, column=0)
    #E2 = ttk.Entry(root2,width=25,textvariable=did)
    E1.grid(row=1, column=4)

    tk.Label(root2, text="NAME").grid(row=2, column=0)
    #E2=ttk.Entry(root2,width=25,textvariable=NAME)
    E2.grid(row=2, column=4)

    tk.Label(root2, text="AGE").grid(row=3, column=0)
    #E3=ttk.Entry(root2,width=25,textvariable=AGE)
    E3.grid(row=3, column=4)

    tk.Label(root2, text="CONTACT_NO").grid(row=4, column=0)
    #E4=tk.Entry(root2,width=25,textvariable=CONTACT_NO)
    E4.grid(row=4, column=4)

    tk.Label(root2, text="GENDER").grid(row=5, column=0)
    #E5=tk.Entry(root2,width=25,textvariable=GENDER)
    E5.grid(row=5, column=4)

    tk.Label(root2, text="ADDRESS").grid(row=6, column=0)
    # E5=tk.Entry(root2,width=25,textvariable=ADDRESS)
    E6.grid(row=6, column=4)

    tk.Label(root2, text="BLOOD_GROUP").grid(row=7, column=0)
    # E5=tk.Entry(root2,width=25,textvariable=BLOOD_GROUP)
    E7.grid(row=7, column=4)

    tk.Button(root2, text='INSERT', command=insert2).grid(row=8, column=0)
    #E1.delete(0, "end")
    #E2.delete(0, "end")

def insert2():
    with closing(sqlite3.connect(file)) as conn:
        with closing(conn.cursor()) as c:
            try:
                c.execute("create table if not exists donar(d_Id integer,d_name varchar(20),d_age integer,d_contact_no integer,d_gender varchar(1),d_address varchar(20),d_blood_group varchar(5),PRIMARY KEY(d_Id));")
            except:
                print("db table creation ERROR")
            did = E1.get()
            name = E2.get()
            age = E3.get()
            contact = E4.get()
            gender = E5.get()
            address = E6.get()
            blood_group = E7.get()
            c.execute("""INSERT INTO donar VALUES(?, ?, ?, ?, ? ,?, ?)""", (did, name, age, contact, gender, address, blood_group))
            conn.commit()
            print("Inserted successfully")


b1 = tk.Button(root1, text="RETRIVE", bg="grey", command=)
b1.place(relx=0.70, rely=0.9, relwidth=0.2, relheight=0.05)

b2 = tk.Button(root1, text="UPDATE", bg="grey", command=update)
b2.place(relx=0.50, rely=0.9, relwidth=0.2, relheight=0.05)

b3 = tk.Button(root1, text="DELETE", bg="grey", command=delete)
b3.place(relx=0.05, rely=0.9, relwidth=0.2, relheight=0.05)

b4 = tk.Button(root1, text="INSERT", bg="grey", command=insert)
b4.place(relx=0.25, rely=0.9, relwidth=0.2, relheight=0.05)

root1.mainloop()



