import os, re
from PIL import Image
import stepic
import shutil
from flask import Blueprint, current_app, render_template, url_for, redirect, request, session, flash
from datetime import timedelta
# from flask_wtf import FlaskForm
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES


text = Blueprint("text", __name__, static_folder="static",
                 template_folder="templates")


@text.route("/encode")
def text_encode():
    if os.path.exists(current_app.config['TEXT_CACHE_FOLDER']):
        shutil.rmtree(
            current_app.config['TEXT_CACHE_FOLDER'], ignore_errors=False)
    else:
        print("Not Found")

    if os.path.exists(os.path.join(current_app.config['UPLOAD_TEXT_FOLDER'], "encrypted_text_image.png")):
        # print("Found")
        os.remove(os.path.join(
            current_app.config['UPLOAD_TEXT_FOLDER'], "encrypted_text_image.png"))
    else:
        print("Not found")
    return render_template("encode-text.html")


@text.route("/encode-result", methods=['POST', 'GET'])
def text_encode_result():
    if request.method == 'POST':
        message = request.form['message']
        key = request.form['Key']
        if 'file' not in request.files:
            flash('No image found')
        file = request.files['image']

        if file.filename == '':
            flash('No image selected')

        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(
                current_app.config['UPLOAD_TEXT_FOLDER'], filename))
            text_encryption = True
            Encryptmessage = AesEncoding(key, message)
            encrypt_text(os.path.join(
                current_app.config['UPLOAD_TEXT_FOLDER'], filename), Encryptmessage)
        else:
            text_encryption = False
        result = request.form

        return render_template("encode-text-result.html", result=result, file=file, text_encryption=text_encryption, message=message)


@text.route("/decode")
def text_decode():
    return render_template("decode-text.html")


@text.route("/decode-result", methods=['POST', 'GET'])
def text_decode_result():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No image found')
        file = request.files['image']
        if file.filename == '':
            flash('No image selected')
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(
                current_app.config['UPLOAD_TEXT_FOLDER'], filename))
            text_decryption = True
            message = decrypt_text(os.path.join(
                current_app.config['UPLOAD_TEXT_FOLDER'], filename))
            key = request.form['Key']
            message = AesDecoding(key, message)
        else:
            text_decryption = False
        result = request.form
        return render_template("decode-text-result.html", result=result, file=file, text_decryption=text_decryption, message=message)

# Encryption function


def encrypt_text(image_1, message):
    im = Image.open(image_1)

    im1 = stepic.encode(im, bytes(str(message), encoding='utf-8'))
    im1.save(os.path.join(
        current_app.config['UPLOAD_TEXT_FOLDER'], "encrypted_text_image.png"))

# Decryption function


def decrypt_text(image_1):
    im2 = Image.open(image_1)
    stegoImage = stepic.decode(im2)
    return stegoImage

# AES Encoding

def AesEncoding(key, message):
    key = bytes(key, 'utf-8')
    message = bytes(message, 'utf-8')
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    file_out = open("encrypted.bin", "wb")
    [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
    file_out.close()
    return ciphertext

# AES Decoding

def AesDecoding(key, message):
    key = bytes(key, 'utf-8')
    file_in = open("encrypted.bin", "rb")
    nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]
    try:
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)
    except :
        flash("WRONG KEY")
        return 
    return data.decode()



    