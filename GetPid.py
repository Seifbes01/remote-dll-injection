import psutil

def get_pid(name):
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == name:
            return proc.info['pid']
    return None

