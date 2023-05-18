import os


async def uploadimage(file):
    photos_dir_list = os.listdir("\\\\fs-mo\\ADMINS\\Photo_warehouse\\photos")
    with open('image.jpg', 'wb') as image:
        image.write(file)
        image.close()
    return 'got it'
