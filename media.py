from abc import ABC, abstractmethod
from PIL import Image
import numpy as np
from pydub import AudioSegment
import os
import logging
from utils import bytes_to_binary, binary_to_bytes

class MediaHandler(ABC):
    """Abstract base class for media handling."""
    
    @abstractmethod
    def encode(self, media_file: str, data: bytes, output_file: str) -> None:
        pass

    @abstractmethod
    def decode(self, media_file: str) -> bytes:
        pass

    @abstractmethod
    def get_max_data_size(self, media_file: str) -> int:
        pass

class ImageHandler(MediaHandler):
    """Handles steganography in images using LSB."""
    
    def encode(self, media_file: str, data: bytes, output_file: str) -> None:
        """Encode data into an image.
        
        Args:
            media_file (str): Path to the input image.
            data (bytes): Data to encode.
            output_file (str): Path to save the output image.
        
        Raises:
            TypeError: If data is not bytes.
            ValueError: If data is too large or encoding fails.
        """
        if not isinstance(data, bytes):
            raise TypeError(f"Expected bytes for data, got {type(data)}")
        logging.debug(f"Encoding data: {data[:10]}... (length: {len(data)} bytes)")
        try:
            img = Image.open(media_file).convert('RGB')
            pixels = img.load()
            width, height = img.size
            binary_data = bytes_to_binary(data) + '1111111100000000'
            if len(binary_data) > width * height * 3:
                raise ValueError("Data too large for image")
            
            data_index = 0
            for y in range(height):
                for x in range(width):
                    r, g, b = pixels[x, y]
                    channels = [r, g, b]
                    for i in range(3):
                        if data_index < len(binary_data):
                            channels[i] = (channels[i] & ~1) | int(binary_data[data_index])
                            data_index += 1
                    pixels[x, y] = tuple(channels)
                    if data_index >= len(binary_data):
                        img.save(output_file, format=os.path.splitext(output_file)[1][1:].upper() or "PNG")
                        logging.info(f"Encoded data into {output_file}")
                        return
            img.save(output_file, format=os.path.splitext(output_file)[1][1:].upper() or "PNG")
            logging.info(f"Encoded data into {output_file}")
        except Exception as e:
            logging.error(f"Image encoding error: {e}")
            raise ValueError(f"Failed to encode data into image: {e}")

    def decode(self, media_file: str) -> bytes:
        """Decode data from an image.
        
        Args:
            media_file (str): Path to the image.
        
        Returns:
            bytes: The decoded data.
        
        Raises:
            ValueError: If decoding fails or marker not found.
        """
        try:
            img = Image.open(media_file).convert('RGB')
            pixels = img.load()
            width, height = img.size
            binary_data = ''
            marker = '1111111100000000'
            for y in range(height):
                for x in range(width):
                    r, g, b = pixels[x, y]
                    binary_data += str(r & 1) + str(g & 1) + str(b & 1)
                    if binary_data.endswith(marker):
                        return binary_to_bytes(binary_data[:-len(marker)])
            if not binary_data.endswith(marker):
                raise ValueError("Marker not found in image data")
        except Exception as e:
            logging.error(f"Image decoding error: {e}")
            raise ValueError(f"Failed to decode image: {e}")

    def get_max_data_size(self, media_file: str) -> int:
        """Calculate the maximum data size that can be encoded.
        
        Args:
            media_file (str): Path to the image.
        
        Returns:
            int: Maximum bytes that can be encoded.
        """
        try:
            img = Image.open(media_file).convert('RGB')
            width, height = img.size
            return (width * height * 3 - 16) // 8  # Subtract marker size
        except Exception as e:
            logging.error(f"Error calculating image max size: {e}")
            return 0

class AudioHandler(MediaHandler):
    """Handles steganography in audio files using LSB."""
    
    def encode(self, media_file: str, data: bytes, output_file: str) -> None:
        """Encode data into an audio file.
        
        Args:
            media_file (str): Path to the input audio.
            data (bytes): Data to encode.
            output_file (str): Path to save the output audio.
        
        Raises:
            TypeError: If data is not bytes.
            ValueError: If data is too large or encoding fails.
        """
        if not isinstance(data, bytes):
            raise TypeError(f"Expected bytes for data, got {type(data)}")
        logging.debug(f"Encoding audio data: {data[:10]}... (length: {len(data)} bytes)")
        try:
            audio = AudioSegment.from_file(media_file)
            samples = np.array(audio.get_array_of_samples(), dtype=np.int16)
            binary_data = bytes_to_binary(data) + '1111111100000000'  # Marker
            if len(binary_data) > len(samples):
                raise ValueError("Data too large for audio")
            for i in range(min(len(binary_data), len(samples))):
                samples[i] = (samples[i] & ~1) | int(binary_data[i])
            new_audio = AudioSegment(
                samples.tobytes(),
                frame_rate=audio.frame_rate,
                sample_width=audio.sample_width,
                channels=audio.channels
            )
            file_format = os.path.splitext(output_file)[1][1:] or "wav"
            new_audio.export(output_file, format=file_format)
            logging.info(f"Encoded data into {output_file}")
        except Exception as e:
            logging.error(f"Audio encoding error: {e}")
            raise ValueError(f"Failed to encode audio: {e}")

    def decode(self, media_file: str) -> bytes:
        """Decode data from an audio file.
        
        Args:
            media_file (str): Path to the audio.
        
        Returns:
            bytes: The decoded data.
        
        Raises:
            ValueError: If decoding fails or marker not found.
        """
        try:
            audio = AudioSegment.from_file(media_file)
            samples = np.array(audio.get_array_of_samples(), dtype=np.int16)
            binary_data = ''
            marker = '1111111100000000'
            for sample in samples:
                binary_data += str(sample & 1)
                if binary_data.endswith(marker):
                    return binary_to_bytes(binary_data[:-len(marker)])
            if not binary_data.endswith(marker):
                raise ValueError("Marker not found in audio data")
        except Exception as e:
            logging.error(f"Audio decoding error: {e}")
            raise ValueError(f"Failed to decode audio: {e}")

    def get_max_data_size(self, media_file: str) -> int:
        """Calculate the maximum data size that can be encoded.
        
        Args:
            media_file (str): Path to the audio.
        
        Returns:
            int: Maximum bytes that can be encoded.
        """
        try:
            audio = AudioSegment.from_file(media_file)
            return (len(audio.get_array_of_samples()) - 16) // 8  # Subtract marker size
        except Exception as e:
            logging.error(f"Error calculating audio max size: {e}")
            return 0