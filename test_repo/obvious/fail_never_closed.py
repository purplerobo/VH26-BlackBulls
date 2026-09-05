def leaky_file_read():
    f = open("dummy.txt", "r")
    data = f.read()
    print("Reading data...")
    return data
    f.close()  # [LeakGuard Auto-Patch]
