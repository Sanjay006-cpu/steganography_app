from abc import ABC, abstractmethod
from PIL import Image
import numpy as np
from pydub import AudioSegment
import os
import logging
from utils import bytes_to_binary, binary_to_bytes

class MediaHandler(ABC):
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
    def encode(self, media_file: str, data: bytes, output_file: str) -> None:
        if not isinstance(data, bytes):
            raise TypeError(f"Expected bytes for data, got {type(data)}")
        logging.debug(f"Encoding data: {data[:10]}... (length: {len(data)} bytes)")
        try:
            img = Image.open(media_file)
            if img.mode != 'RGB':
                img = img.convert('RGB')
            pixels = img.load()
            width, height = img.size
            binary_data = bytes_to_binary(data) + '1111111100000000'
            if len(binary_data) > width * height * 3:
                raise ValueError("Data too large for image")
            data_index = 0
            for y in range(height):
                for x in range(width):
                    r, g, b = pixels[x, y]
                    if data_index < len(binary_data):
                        r = (r & ~1) | int(binary_data[data_index])
                        data_index += 1
                    if data_index < len(binary_data):
                        g = (g & ~1) | int(binary_data[data_index])
                        data_index += 1
                    if data_index < len(binary_data):
                        b = (b & ~1) | int(binary_data[data_index])
                        data_index += 1
                    pixels[x, y] = (r, g, b)
                    if data_index >= len(binary_data):
                        break
                if data_index >= len(binary_data):
                    break
            file_format = os.path.splitext(output_file)[1][1:].upper() or "PNG"
            img.save(output_file, format=file_format)
            logging.info(f"Encoded data into {output_file}")
        except Exception as e:
            logging.error(f"Image encoding error: {e}")
            raise ValueError(f"Failed to encode data into image: {e}")

    def decode(self, media_file: str) -> bytes:
        try:
            img = Image.open(media_file)
            if img.mode != 'RGB':
                img = img.convert('RGB')
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
            max_bits = width * height * 3
            logging.warning("No marker found during image decode")
            return binary_to_bytes(binary_data[:max_bits])
        except Exception as e:
            logging.error(f"Image decoding error: {e}")
            raise ValueError(f"Failed to decode image: {e}")

    def get_max_data_size(self, media_file: str) -> int:
        try:
            img = Image.open(media_file)
            if img.mode != 'RGB':
                img = img.convert('RGB')
            width, height = img.size
            return (width * height * 3 - 16) // 8
        except Exception as e:
            logging.error(f"Error calculating image max size: {e}")
            return 0

class AudioHandler(MediaHandler):
    def encode(self, media_file: str, data: bytes, output_file: str) -> None:
        if not isinstance(data, bytes):
            raise TypeError(f"Expected bytes for data, got {type(data)}")
        logging.debug(f"Encoding audio data: {data[:10]}... (length: {len(data)} bytes)")
        try:
            audio = AudioSegment.from_file(media_file)
            samples = np.array(audio.get_array_of_samples(), dtype=np.int16)
            binary_data = bytes_to_binary(data) + '1111111100000000'
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
        try:
            audio = AudioSegment.from_file(media_file)
            samples = np.array(audio.get_array_of_samples(), dtype=np.int16)
            binary_data = ''
            marker = '1111111100000000'
            for sample in samples:
                binary_data += str(sample & 1)
                if binary_data.endswith(marker):
                    return binary_to_bytes(binary_data[:-len(marker)])
            logging.warning("No marker found during audio decode")
            return binary_to_bytes(binary_data[:len(samples)])
        except Exception as e:
            logging.error(f"Audio decoding error: {e}")
            raise ValueError(f"Failed to decode audio: {e}")

    def get_max_data_size(self, media_file: str) -> int:
        try:
            audio = AudioSegment.from_file(media_file)
            return (len(audio.get_array_of_samples()) - 16) // 8
        except Exception as e:
            logging.error(f"Error calculating audio max size: {e}")
            return 0