# audio_utils.py

import tkinter as tk
from tkinter import messagebox
import soundfile as sf
import numpy as np
import hashlib
import os
import speech_recognition as sr
import time
import threading
import pyaudio
import wave

RECORD_SECONDS = 5
CHUNK = 1024
FORMAT = pyaudio.paInt16
CHANNELS = 1
RATE = 16000

def extract_audio_features(voice_file):
    y, sr = sf.read(voice_file)
    mfcc_features = np.mean(y)
    feature_hash = hashlib.blake2b(str(mfcc_features).encode()).hexdigest()
    return feature_hash

def get_voice_features():
    result = []

    voice_window = tk.Toplevel()
    voice_window.title("🎙️ Voice Input")
    voice_window.geometry("350x300")
    voice_window.configure(bg="#f8f9fa")

    tk.Label(voice_window, text="Press the button to record", fg="#212529", bg="#f8f9fa",
             font=("Segoe UI", 11)).pack(pady=10)

    countdown_label = tk.Label(voice_window, text="", fg="#0d6efd", bg="#f8f9fa", font=("Segoe UI", 28))
    countdown_label.pack(pady=10)

    canvas = tk.Canvas(voice_window, width=300, height=100, bg="#ffffff", highlightthickness=1, highlightbackground="#dee2e6")
    canvas.pack(pady=5)

    meter_bar = canvas.create_rectangle(0, 100, 0, 0, fill="#0d6efd", outline="")

    # Button to start recording
    record_btn = tk.Button(voice_window, text="Start Recording", font=("Segoe UI", 12), bg="#0d6efd", fg="white")
    record_btn.pack(pady=20)

    def draw_audio_meter(data):
        amplitude = np.frombuffer(data, dtype=np.int16)
        level = int(np.linalg.norm(amplitude) / 1000)
        level = min(level, 100)
        canvas.coords(meter_bar, 0, 100 - level, 300, 100)

    def finish_recording(frames, p, stream, temp_filename):
        stream.stop_stream()
        stream.close()
        p.terminate()
        # Save to temp file
        wf = wave.open(temp_filename, 'wb')
        wf.setnchannels(CHANNELS)
        wf.setsampwidth(p.get_sample_size(FORMAT))
        wf.setframerate(RATE)
        wf.writeframes(b''.join(frames))
        wf.close()
        # Extract features
        feature_hash = extract_audio_features(temp_filename)
        result.append(feature_hash)
        # Clean up temp file
        if os.path.exists(temp_filename):
            os.remove(temp_filename)
        countdown_label.config(text="Done!")
        record_btn.config(state=tk.NORMAL)
        voice_window.after(1000, voice_window.destroy)

    def update_audio(stream, frames, start_time, p, temp_filename):
        elapsed = time.time() - start_time
        if elapsed < RECORD_SECONDS:
            data = stream.read(CHUNK, exception_on_overflow=False)
            frames.append(data)
            draw_audio_meter(data)
            countdown_label.config(text=str(RECORD_SECONDS - int(elapsed)))
            voice_window.after(50, update_audio, stream, frames, start_time, p, temp_filename)
        else:
            finish_recording(frames, p, stream, temp_filename)

    def start_recording():
        record_btn.config(state=tk.DISABLED)
        countdown_label.config(text="5")
        voice_window.update()
        # Wait a moment before starting to record
        voice_window.after(500, begin_recording)

    def begin_recording():
        p = pyaudio.PyAudio()
        stream = p.open(format=FORMAT, channels=CHANNELS, rate=RATE,
                        input=True, frames_per_buffer=CHUNK)
        frames = []
        temp_filename = "temp_voice_input.wav"
        start_time = time.time()
        countdown_label.config(text=str(RECORD_SECONDS))
        update_audio(stream, frames, start_time, p, temp_filename)

    record_btn.config(command=start_recording)

    voice_window.grab_set()
    voice_window.wait_window()
    return result[0] if result else None
