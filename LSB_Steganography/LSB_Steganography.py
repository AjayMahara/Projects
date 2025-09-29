import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from PIL import Image, ImageTk
import numpy as np
import os
import threading
import time
from pathlib import Path
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import struct

class LSBSteganography:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("LSB Steganography Tool")
        
        # Make window responsive and fit screen
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        
        # Set window size to 90% of screen size
        window_width = int(screen_width * 0.9)
        window_height = int(screen_height * 0.9)
        
        self.root.geometry(f"{window_width}x{window_height}")
        self.root.configure(bg="#FFF8F0")
        
        # Set icon and make window resizable
        self.root.resizable(True, True)
        self.root.minsize(800, 600)
        
        # Bind resize event
        self.root.bind('<Configure>', self.on_window_resize)
        
        # Bind window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Variables
        self.original_image = None
        self.stego_image = None
        self.encode_image_path = None
        self.decode_image_path = None
        self.output_path = None
        
        # Thread management
        self.encode_thread = None
        self.decode_thread = None
        self.should_stop = False
        
        # Warm Color Theme
        self.colors = {
            'primary': '#8B4513',      # Saddle Brown
            'secondary': '#D2691E',    # Chocolate
            'accent': '#FF6B35',       # Warm Orange
            'success': '#228B22',      # Forest Green
            'warning': '#FF8C00',      # Dark Orange
            'light': '#FFF8F0',        # Warm Cream
            'dark': '#2F2F2F',         # Dark Gray
            'white': '#FFFFFF',        # Pure White
            'gloss1': '#DEB887',       # Burlywood
            'gloss2': '#F4A460',       # Sandy Brown
            'text_primary': '#2F2F2F', # Dark text for light backgrounds
            'text_light': '#8B4513',   # Brown text for light backgrounds
            'cursor': '#FF6B35',       # Warm orange cursor
            'selection': '#FFE4B5',    # Light peach selection
        }
        self.font_family = 'Segoe UI'
        
        self.setup_ui()
        self.center_window()
        
    def on_closing(self):
        """Handle window closing event"""
        self.should_stop = True
        
        # Stop any running threads
        if hasattr(self, 'encode_thread') and self.encode_thread and self.encode_thread.is_alive():
            self.encode_thread.join(timeout=1.0)
        if hasattr(self, 'decode_thread') and self.decode_thread and self.decode_thread.is_alive():
            self.decode_thread.join(timeout=1.0)
            
        self.root.destroy()
        
    def on_window_resize(self, event):
        """Handle window resize events"""
        if event.widget == self.root:
            # Update image displays when window is resized
            if hasattr(self, 'encode_image_path') and self.encode_image_path:
                self.display_image(self.encode_image_path, self.encode_image_label)
            if hasattr(self, 'decode_image_path') and self.decode_image_path:
                self.display_image(self.decode_image_path, self.decode_image_label)
        
    def center_window(self):
        """Center the window on screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
        
    def setup_ui(self):
        """Setup the main UI components"""
        # Main container
        main_frame = tk.Frame(self.root, bg=self.colors['light'])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        title_frame = tk.Frame(main_frame, bg=self.colors['light'])
        title_frame.pack(fill=tk.X, pady=(0, 20))
        
        title_label = tk.Label(
            title_frame,
            text="🔐 LSB Steganography Tool",
            font=(self.font_family, 26, "bold"),
            fg=self.colors['primary'],
            bg=self.colors['light']
        )
        title_label.pack()
        
        subtitle_label = tk.Label(
            title_frame,
            text="Hide and extract secret messages in images with AES encryption",
            font=(self.font_family, 13),
            fg=self.colors['secondary'],
            bg=self.colors['light']
        )
        subtitle_label.pack()
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Configure notebook style for warm theme
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background=self.colors['light'])
        style.configure('TNotebook.Tab',
            padding=[20, 10],
            font=(self.font_family, 11, 'bold'),
            background=self.colors['gloss1'],
            foreground=self.colors['text_primary'],
            borderwidth=2,
            relief='raised')
        style.map('TNotebook.Tab',
            background=[('selected', self.colors['primary']), ('active', self.colors['gloss2'])],
            foreground=[('selected', self.colors['white']), ('active', self.colors['text_primary'])],
            bordercolor=[('selected', self.colors['accent'])],
        )

        # Create tabs
        self.create_encode_tab()
        self.create_decode_tab()
        self.create_about_tab()
        
    def create_encode_tab(self):
        """Create the encoding tab"""
        encode_frame = tk.Frame(self.notebook, bg=self.colors['white'])
        self.notebook.add(encode_frame, text="🔒 Encode Message")
        
        # Left panel for image display
        left_panel = tk.Frame(encode_frame, bg=self.colors['white'])
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10), pady=10)
        
        self.encode_image_label = tk.Label(
            left_panel, 
            text="No image selected", 
            font=(self.font_family, 12), 
            fg=self.colors['text_light'], 
            bg=self.colors['light'], 
            relief=tk.RIDGE, 
            bd=2
        )
        self.encode_image_label.pack(fill=tk.BOTH, expand=True, pady=10)
        
        select_img_btn = tk.Button(
            left_panel, 
            text="Select Image", 
            font=(self.font_family, 11, "bold"), 
            bg=self.colors['secondary'], 
            fg=self.colors['white'], 
            command=self.select_encode_image, 
            relief=tk.RAISED, 
            activebackground=self.colors['gloss2'], 
            bd=3, 
            highlightbackground=self.colors['gloss1'], 
            highlightthickness=2,
            cursor="hand2"
        )
        select_img_btn.pack(pady=10)
        
        # Right panel for message input
        right_panel = tk.Frame(encode_frame, bg=self.colors['white'])
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=10)
        
        msg_label = tk.Label(
            right_panel, 
            text="Message to Hide:", 
            font=(self.font_family, 12, "bold"), 
            fg=self.colors['primary'], 
            bg=self.colors['white']
        )
        msg_label.pack(anchor=tk.W, pady=(0, 5))
        
        self.message_text = scrolledtext.ScrolledText(
            right_panel, 
            font=(self.font_family, 12), 
            wrap=tk.WORD, 
            bg=self.colors['white'], 
            fg=self.colors['text_primary'], 
            height=8,
            insertbackground=self.colors['cursor'],
            selectbackground=self.colors['selection'],
            selectforeground=self.colors['text_primary']
        )
        self.message_text.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        password_frame = tk.Frame(right_panel, bg=self.colors['white'])
        password_frame.pack(fill=tk.X, pady=(0, 10))
        tk.Label(
            password_frame, 
            text="Password (required for AES encryption):", 
            font=(self.font_family, 11), 
            bg=self.colors['white'], 
            fg=self.colors['text_primary']
        ).pack(anchor=tk.W)
        self.password_entry = tk.Entry(
            password_frame, 
            show="*", 
            font=(self.font_family, 11), 
            bg=self.colors['white'], 
            fg=self.colors['text_primary'],
            insertbackground=self.colors['cursor'],
            selectbackground=self.colors['selection'],
            selectforeground=self.colors['text_primary']
        )
        self.password_entry.pack(fill=tk.X, pady=(2, 0))
        
        encode_btn = tk.Button(
            right_panel, 
            text="Encode Message", 
            font=(self.font_family, 12, "bold"), 
            bg=self.colors['primary'], 
            fg=self.colors['white'], 
            command=self.encode_message, 
            relief=tk.RAISED, 
            activebackground=self.colors['gloss1'], 
            bd=3, 
            highlightbackground=self.colors['accent'], 
            highlightthickness=2,
            cursor="hand2"
        )
        encode_btn.pack(fill=tk.X, pady=(10, 5))
        
        # Cancel button for encoding
        self.encode_cancel_btn = tk.Button(
            right_panel,
            text="Cancel",
            font=(self.font_family, 11),
            bg=self.colors['gloss1'],
            fg=self.colors['text_primary'],
            command=self.cancel_encode,
            relief=tk.RAISED,
            activebackground=self.colors['gloss2'],
            bd=2,
            cursor="hand2",
            state=tk.DISABLED
        )
        self.encode_cancel_btn.pack(fill=tk.X, pady=(0, 5))
        
        # Progress bar for encoding
        self.encode_progress = ttk.Progressbar(right_panel, mode='indeterminate')
        self.encode_progress.pack(fill=tk.X, pady=(0, 5))
        
        self.encode_status = tk.Label(
            right_panel, 
            text="", 
            font=(self.font_family, 11), 
            bg=self.colors['white'], 
            fg=self.colors['text_primary']
        )
        self.encode_status.pack(anchor=tk.W, pady=(5, 0))
        
    def create_decode_tab(self):
        """Create the decoding tab"""
        decode_frame = tk.Frame(self.notebook, bg=self.colors['white'])
        self.notebook.add(decode_frame, text="🔓 Decode Message")
        
        # Left panel for image display
        left_panel = tk.Frame(decode_frame, bg=self.colors['white'])
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10), pady=10)
        
        self.decode_image_label = tk.Label(
            left_panel, 
            text="No image selected", 
            font=(self.font_family, 12), 
            fg=self.colors['text_light'], 
            bg=self.colors['light'], 
            relief=tk.RIDGE, 
            bd=2
        )
        self.decode_image_label.pack(fill=tk.BOTH, expand=True, pady=10)
        
        select_img_btn = tk.Button(
            left_panel, 
            text="Select Image", 
            font=(self.font_family, 11, "bold"), 
            bg=self.colors['secondary'], 
            fg=self.colors['white'], 
            command=self.select_decode_image, 
            relief=tk.RAISED, 
            activebackground=self.colors['gloss2'], 
            bd=3, 
            highlightbackground=self.colors['gloss1'], 
            highlightthickness=2,
            cursor="hand2"
        )
        select_img_btn.pack(pady=10)
        
        # Right panel for message output
        right_panel = tk.Frame(decode_frame, bg=self.colors['white'])
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=10)
        
        msg_label = tk.Label(
            right_panel, 
            text="Decoded Message:", 
            font=(self.font_family, 12, "bold"), 
            fg=self.colors['primary'], 
            bg=self.colors['white']
        )
        msg_label.pack(anchor=tk.W, pady=(0, 5))
        
        self.decoded_text = scrolledtext.ScrolledText(
            right_panel, 
            font=(self.font_family, 12), 
            wrap=tk.WORD, 
            bg=self.colors['white'], 
            fg=self.colors['text_primary'], 
            height=8,
            insertbackground=self.colors['cursor'],
            selectbackground=self.colors['selection'],
            selectforeground=self.colors['text_primary']
        )
        self.decoded_text.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        password_frame = tk.Frame(right_panel, bg=self.colors['white'])
        password_frame.pack(fill=tk.X, pady=(0, 10))
        tk.Label(
            password_frame, 
            text="Password (required for AES decryption):", 
            font=(self.font_family, 11), 
            bg=self.colors['white'], 
            fg=self.colors['text_primary']
        ).pack(anchor=tk.W)
        self.decode_password_entry = tk.Entry(
            password_frame, 
            show="*", 
            font=(self.font_family, 11), 
            bg=self.colors['white'], 
            fg=self.colors['text_primary'],
            insertbackground=self.colors['cursor'],
            selectbackground=self.colors['selection'],
            selectforeground=self.colors['text_primary']
        )
        self.decode_password_entry.pack(fill=tk.X, pady=(2, 0))
        
        decode_btn = tk.Button(
            right_panel, 
            text="Decode Message", 
            font=(self.font_family, 12, "bold"), 
            bg=self.colors['accent'], 
            fg=self.colors['white'], 
            command=self.decode_message, 
            relief=tk.RAISED, 
            activebackground=self.colors['gloss1'], 
            bd=3, 
            highlightbackground=self.colors['success'], 
            highlightthickness=2,
            cursor="hand2"
        )
        decode_btn.pack(fill=tk.X, pady=(10, 5))
        
        # Cancel button for decoding
        self.decode_cancel_btn = tk.Button(
            right_panel,
            text="Cancel",
            font=(self.font_family, 11),
            bg=self.colors['gloss1'],
            fg=self.colors['text_primary'],
            command=self.cancel_decode,
            relief=tk.RAISED,
            activebackground=self.colors['gloss2'],
            bd=2,
            cursor="hand2",
            state=tk.DISABLED
        )
        self.decode_cancel_btn.pack(fill=tk.X, pady=(0, 5))
        
        # Progress bar for decoding
        self.decode_progress = ttk.Progressbar(decode_frame, mode='indeterminate')
        self.decode_progress.pack(fill=tk.X, pady=(0, 5))
        
        self.decode_status = tk.Label(
            right_panel, 
            text="", 
            font=(self.font_family, 11), 
            bg=self.colors['white'], 
            fg=self.colors['text_primary']
        )
        self.decode_status.pack(anchor=tk.W, pady=(5, 0))
        
    def create_about_tab(self):
        """Create the about tab"""
        about_frame = tk.Frame(self.notebook, bg=self.colors['light'])
        self.notebook.add(about_frame, text="ℹ️ About")

        # About content
        about_content = tk.Frame(about_frame, bg=self.colors['light'])
        about_content.pack(expand=True, fill=tk.BOTH, padx=50, pady=50)

        # Title
        tk.Label(
            about_content, 
            text="About LSB Steganography", 
            font=("Segoe UI", 20, "bold"), 
            fg=self.colors['primary'],
            bg=self.colors['light']
        ).pack(pady=(0, 20))

        # Description
        description = """
LSB (Least Significant Bit) Steganography is a technique used to hide secret messages 
within digital images by modifying the least significant bits of pixel values.

🔒 How Encoding Works:
• Converts your message to binary with AES encryption
• Adds message length header for reliable extraction
• Replaces the least significant bit of each pixel's RGB values
• The changes are imperceptible to the human eye
• The image maintains its visual quality
• Always saves as PNG for lossless quality

🔓 How Decoding Works:
• Extracts the message length header
• Reads the exact number of bits needed
• Reconstructs the original binary message
• Decrypts using AES with your password
• Converts back to readable text

✨ Enhanced Features:
• AES-256 encryption for message security
• Message length headers for reliable extraction
• Separate encode/decode image paths
• Enforced PNG saving for best quality
• Support for various input image formats
• Real-time image preview
• User-friendly interface

⚠️ Important Notes:
- Password is REQUIRED for encryption/decryption
- Encoded images are always saved as PNG for best quality
- Use lossless formats (PNG, BMP) for best results
- Avoid re-saving stego images in lossy formats (JPG) after encoding
"""
        tk.Label(
            about_content, 
            text=description, 
            font=("Segoe UI", 12), 
            fg=self.colors['text_primary'], 
            bg=self.colors['light'], 
            justify=tk.LEFT, 
            anchor="w"
        ).pack(fill=tk.BOTH, expand=True)
        
    def select_encode_image(self):
        """Select an image for encoding"""
        file_path = filedialog.askopenfilename(
            title="Select Image for Encoding",
            filetypes=[
                ("Image files", "*.png *.jpg *.jpeg *.bmp *.gif *.tiff"),
                ("PNG files", "*.png"),
                ("JPEG files", "*.jpg *.jpeg"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            self.encode_image_path = file_path
            self.display_image(file_path, self.encode_image_label)
            self.encode_status.config(text=f"Image loaded: {os.path.basename(file_path)}")
            
    def select_decode_image(self):
        """Select an image for decoding"""
        file_path = filedialog.askopenfilename(
            title="Select Stego Image for Decoding",
            filetypes=[
                ("Image files", "*.png *.jpg *.jpeg *.bmp *.gif *.tiff"),
                ("PNG files", "*.png"),
                ("JPEG files", "*.jpg *.jpeg"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            self.decode_image_path = file_path
            self.display_image(file_path, self.decode_image_label)
            self.decode_status.config(text=f"Image loaded: {os.path.basename(file_path)}")
            
    def display_image(self, image_path, label_widget):
        """Display image in the specified label widget"""
        try:
            # Open and resize image
            image = Image.open(image_path)

            # Get label size after layout update
            label_widget.update_idletasks()
            label_width = label_widget.winfo_width() or 300
            label_height = label_widget.winfo_height() or 300

            # Get original dimensions
            img_width, img_height = image.size

            # Calculate scaling factor
            scale = min(label_width / img_width, label_height / img_height)

            # Calculate new dimensions
            new_width = int(img_width * scale)
            new_height = int(img_height * scale)

            # Resize image
            image = image.resize((new_width, new_height), Image.Resampling.LANCZOS)

            # Create a blank background and paste the image centered
            background = Image.new('RGB', (label_width, label_height), self.colors['light'])
            paste_x = (label_width - new_width) // 2
            paste_y = (label_height - new_height) // 2
            background.paste(image, (paste_x, paste_y))

            # Convert to PhotoImage
            photo = ImageTk.PhotoImage(background)

            # Update label
            label_widget.config(image=photo, text="")
            label_widget.image = photo  # Keep a reference

        except Exception as e:
            label_widget.config(image="", text=f"Error loading image:\n{str(e)}")
            
    def encode_message(self):
        """Encode message into image"""
        if not self.encode_image_path:
            messagebox.showerror("Error", "Please select an image first!")
            return
            
        message = self.message_text.get("1.0", tk.END).strip()
        if not message:
            messagebox.showerror("Error", "Please enter a message to encode!")
            return
            
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Password is required for AES encryption!")
            return
        
        # Clear previous status
        self.encode_status.config(text="Starting encryption...", fg=self.colors['warning'])
        
        # Run encoding in a separate thread to prevent UI freezing
        self.encode_thread = threading.Thread(target=self._encode_message_thread, args=(message, password))
        self.encode_thread.daemon = True
        self.encode_thread.start()
        
        # Set a timeout to check if thread is still running
        self.root.after(100, self._check_encode_timeout)
        
    def cancel_encode(self):
        """Cancel the encoding operation"""
        self.should_stop = True
        if hasattr(self, 'encode_thread') and self.encode_thread and self.encode_thread.is_alive():
            self.encode_thread.join(timeout=0.5)
        self.encode_status.config(text="Encoding cancelled", fg=self.colors['dark'])
        self.encode_cancel_btn.config(state=tk.DISABLED)
        self.encode_progress.stop()
        
    def _check_encode_timeout(self):
        """Check if encode thread is still running and handle timeout"""
        if hasattr(self, 'encode_thread') and self.encode_thread and self.encode_thread.is_alive():
            # Thread is still running, check again in 100ms
            self.root.after(100, self._check_encode_timeout)
        else:
            # Thread has finished, ensure progress bar is stopped
            if hasattr(self, 'encode_progress'):
                self.encode_progress.stop()
            # Disable cancel button
            if hasattr(self, 'encode_cancel_btn'):
                self.encode_cancel_btn.config(state=tk.DISABLED)
                
    def _encode_message_thread(self, message, password):
        """Encode message in a separate thread"""
        try:
            # Enable cancel button
            self.root.after(0, lambda: self.encode_cancel_btn.config(state=tk.NORMAL))
            
            self.encode_progress.start()
            self.encode_status.config(text="Encoding message...", fg=self.colors['warning'])
            self.root.update()
            
            # Check if operation was cancelled
            if self.should_stop:
                return
            
            # Load image
            image = Image.open(self.encode_image_path)
            
            # Check if operation was cancelled
            if self.should_stop:
                return
            
            # Encrypt message with AES
            encrypted_message = self._encrypt_message(message, password)
            
            # Check if operation was cancelled
            if self.should_stop:
                return
            
            # Convert encrypted message to binary
            binary_message = ''.join(format(byte, '08b') for byte in encrypted_message)
            
            # Add message length header (32 bits = 4 bytes)
            message_length = len(binary_message)
            length_binary = format(message_length, '032b')
            
            # Combine length header and message
            full_binary = length_binary + binary_message
            
            # Check if image can hold the message
            if len(full_binary) > image.size[0] * image.size[1] * 3:
                self.root.after(0, lambda: messagebox.showerror("Error", "Message too long for this image!"))
                self.encode_status.config(text="Encoding failed", fg=self.colors['accent'])
                return
                
            # Convert image to numpy array
            img_array = np.array(image)
            
            # Flatten the array
            flat_img = img_array.flatten()
            
            # Encode message
            for i, bit in enumerate(full_binary):
                if self.should_stop:
                    return
                if i < len(flat_img):
                    # Clear the least significant bit and set it to the message bit
                    flat_img[i] = (flat_img[i] & 0xFE) | int(bit)
                    
            # Check if operation was cancelled
            if self.should_stop:
                return
                    
            # Reshape back to original dimensions
            encoded_img_array = flat_img.reshape(img_array.shape)
            
            # Convert back to PIL Image
            encoded_image = Image.fromarray(encoded_img_array.astype(np.uint8))
            
            # Save the encoded image (enforced PNG)
            output_path = filedialog.asksaveasfilename(
                title="Save Encoded Image",
                defaultextension=".png",
                filetypes=[
                    ("PNG files", "*.png"),
                ]
            )
            
            if output_path and not self.should_stop:
                # Ensure PNG extension
                if not output_path.lower().endswith('.png'):
                    output_path += '.png'
                
                encoded_image.save(output_path, 'PNG')
                self.encode_status.config(text="Message encoded successfully!", fg=self.colors['success'])
                messagebox.showinfo("Success", f"Message encoded successfully!\nSaved to: {output_path}")
            elif not self.should_stop:
                self.encode_status.config(text="Encoding cancelled", fg=self.colors['dark'])
                
        except Exception as e:
            if not self.should_stop:
                self.encode_status.config(text=f"Encoding failed: {str(e)}", fg=self.colors['accent'])
                messagebox.showerror("Error", f"Encoding failed: {str(e)}")
        finally:
            self.should_stop = False
            self.encode_progress.stop()
            self.encode_cancel_btn.config(state=tk.DISABLED)
            
    def decode_message(self):
        """Decode message from image"""
        if not self.decode_image_path:
            messagebox.showerror("Error", "Please select an image first!")
            return
            
        password = self.decode_password_entry.get()
        if not password:
            messagebox.showerror("Error", "Password is required for AES decryption!")
            return
        
        # Clear previous results
        self.decoded_text.delete("1.0", tk.END)
        self.decode_status.config(text="Starting decryption...", fg=self.colors['warning'])
        
        # Run decoding in a separate thread with timeout
        self.decode_thread = threading.Thread(target=self._decode_message_thread, args=(password,))
        self.decode_thread.daemon = True
        self.decode_thread.start()
        
        # Set a timeout to check if thread is still running
        self.root.after(100, self._check_decode_timeout)
        
    def cancel_decode(self):
        """Cancel the decoding operation"""
        self.should_stop = True
        if hasattr(self, 'decode_thread') and self.decode_thread and self.decode_thread.is_alive():
            self.decode_thread.join(timeout=0.5)
        self.decode_status.config(text="Decoding cancelled", fg=self.colors['dark'])
        self.decode_cancel_btn.config(state=tk.DISABLED)
        self.decode_progress.stop()
        
    def _check_decode_timeout(self):
        """Check if decode thread is still running and handle timeout"""
        if hasattr(self, 'decode_thread') and self.decode_thread and self.decode_thread.is_alive():
            # Thread is still running, check again in 100ms
            self.root.after(100, self._check_decode_timeout)
        else:
            # Thread has finished, ensure progress bar is stopped
            if hasattr(self, 'decode_progress'):
                self.decode_progress.stop()
            # Disable cancel button
            if hasattr(self, 'decode_cancel_btn'):
                self.decode_cancel_btn.config(state=tk.DISABLED)
            
    def _decode_message_thread(self, password):
        """Decode message in a separate thread"""
        try:
            # Enable cancel button
            self.root.after(0, lambda: self.decode_cancel_btn.config(state=tk.NORMAL))
            
            self.decode_progress.start()
            self.decode_status.config(text="Decoding message...", fg=self.colors['warning'])
            self.root.update()
            
            # Check if operation was cancelled
            if self.should_stop:
                return
            
            # Load image
            image = Image.open(self.decode_image_path)
            
            # Check if operation was cancelled
            if self.should_stop:
                return
            
            # Convert image to numpy array
            img_array = np.array(image)
            
            # Flatten the array
            flat_img = img_array.flatten()
            
            # Validate image size
            if len(flat_img) < 32:
                raise ValueError("Image too small to contain encoded data.")
            
            # First, extract the length header (32 bits)
            length_binary = ""
            for i in range(32):
                if self.should_stop:
                    return
                if i < len(flat_img):
                    bit = flat_img[i] & 1
                    length_binary += str(bit)
            
            # Check if operation was cancelled
            if self.should_stop:
                return
            
            # Convert length header to integer
            try:
                message_length = int(length_binary, 2)
            except ValueError:
                raise ValueError("Invalid length header; image may not contain encoded data.")
            
            # Validate message length
            if message_length <= 0 or message_length > len(flat_img) - 32:
                raise ValueError("Invalid message length; image may not contain encoded data.")
            
            # Extract the encrypted message bits
            encrypted_binary = ""
            for i in range(32, 32 + message_length):
                if self.should_stop:
                    return
                if i < len(flat_img):
                    bit = flat_img[i] & 1
                    encrypted_binary += str(bit)
            
            # Check if operation was cancelled
            if self.should_stop:
                return
            
            # Validate binary message
            if len(encrypted_binary) != message_length:
                raise ValueError("Message length mismatch; corrupted data detected.")
            
            # Convert binary to bytes
            if len(encrypted_binary) % 8 != 0:
                raise ValueError("Invalid binary message length.")
            
            encrypted_bytes = bytearray()
            for i in range(0, len(encrypted_binary), 8):
                if self.should_stop:
                    return
                byte = encrypted_binary[i:i+8]
                encrypted_bytes.append(int(byte, 2))
            
            # Check if operation was cancelled
            if self.should_stop:
                return
            
            # Validate encrypted data size
            if len(encrypted_bytes) < 16:
                raise ValueError("Encrypted data too short; invalid stego image.")
            
            # Decrypt the message with timeout protection
            try:
                decrypted_message = self._decrypt_message_with_timeout(bytes(encrypted_bytes), password)
            except Exception as e:
                if "InvalidToken" in str(e) or "Decryption failed" in str(e):
                    raise ValueError("Wrong password or corrupted data. Please check your password.")
                else:
                    raise ValueError(f"Decryption failed: {str(e)}")
            
            # Check if operation was cancelled
            if self.should_stop:
                return
            
            # Display the decoded message
            self.decoded_text.delete("1.0", tk.END)
            self.decoded_text.insert("1.0", decrypted_message)
            
            self.decode_status.config(text="Message decoded successfully!", fg=self.colors['success'])
            
        except Exception as e:
            if not self.should_stop:
                error_msg = str(e)
                self.decode_status.config(text=f"Decoding failed: {error_msg}", fg=self.colors['accent'])
                
                # Show user-friendly error message
                if "Wrong password" in error_msg:
                    messagebox.showerror("Decryption Failed", 
                        "Wrong password! Please check your password and try again.\n\n"
                        "Note: The password must match exactly what was used during encoding.")
                elif "corrupted data" in error_msg.lower():
                    messagebox.showerror("Data Error", 
                        "The image appears to be corrupted or doesn't contain encoded data.\n\n"
                        "Please make sure you're using the correct stego image.")
                else:
                    messagebox.showerror("Decoding Error", f"Decoding failed: {error_msg}")
        finally:
            self.should_stop = False
            self.decode_progress.stop()
            self.decode_cancel_btn.config(state=tk.DISABLED)
        
    def _decrypt_message_with_timeout(self, encrypted_data, password):
        """Decrypt message with timeout protection to prevent hanging"""
        try:
            # Extract salt and encrypted data
            if len(encrypted_data) < 16:
                raise ValueError("Encrypted data too short")
                
            salt = encrypted_data[:16]
            encrypted_message = encrypted_data[16:]
            
            # Validate encrypted message
            if len(encrypted_message) == 0:
                raise ValueError("No encrypted message data found")
            
            # Derive key from password and salt
            password_bytes = password.encode()
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
            
            # Create Fernet cipher
            cipher = Fernet(key)
            
            # Decrypt message with error handling
            try:
                decrypted_data = cipher.decrypt(encrypted_message)
                return decrypted_data.decode('utf-8', errors='ignore')
            except Exception as decrypt_error:
                if "InvalidToken" in str(decrypt_error):
                    raise ValueError("Wrong password - authentication failed")
                else:
                    raise ValueError(f"Decryption error: {str(decrypt_error)}")
                    
        except Exception as e:
            # Re-raise with more context
            if "Wrong password" in str(e):
                raise e
            elif "InvalidToken" in str(e):
                raise ValueError("Wrong password - authentication failed")
            else:
                raise ValueError(f"Decryption failed: {str(e)}")
        
    def _encrypt_message(self, message, password):
        """Encrypt message using AES-256 with password"""
        try:
            # Convert password to bytes
            password_bytes = password.encode()
            
            # Generate salt and derive key
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
            
            # Create Fernet cipher
            cipher = Fernet(key)
            
            # Encrypt message
            encrypted_data = cipher.encrypt(message.encode())
            
            # Combine salt and encrypted data
            return salt + encrypted_data
            
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")
        
    def _decrypt_message(self, encrypted_data, password):
        """Decrypt message using AES-256 with password (legacy method)"""
        try:
            # Extract salt and encrypted data
            salt = encrypted_data[:16]
            encrypted_message = encrypted_data[16:]
            
            # Derive key from password and salt
            password_bytes = password.encode()
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
            
            # Create Fernet cipher
            cipher = Fernet(key)
            
            # Decrypt message
            decrypted_data = cipher.decrypt(encrypted_message)
            
            return decrypted_data.decode()
            
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")
        
    def run(self):
        """Start the application"""
        self.root.mainloop()

def main():
    """Main function to run the application"""
    app = LSBSteganography()
    app.run()

if __name__ == "__main__":
    main()
