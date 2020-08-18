import os

# it will get file lists of directory whose path is directory_path
directory_path = 'data'

if __name__ == '__main__':
    # parameter: path of directory
    file_list = os.listdir(directory_path)
    for fl in file_list:
        print(fl)
