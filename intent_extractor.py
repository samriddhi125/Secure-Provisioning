from flask import Flask, request, jsonify, session
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import json
import os
from datetime import timedelta
import secrets
import re
from few_shot import FewShotIntentExtractor


class IntentExtractor():
    intent_extractor=FewShotIntentExtractor()
    def __init__(self):     
        intent_extractor = FewShotIntentExtractor()


    def get_nested_value(self, data_dict, keys):
        """Safely retrieve a value from a nested dictionary."""
        temp_dict = data_dict
        for key in keys:
            if isinstance(temp_dict, dict):
                temp_dict = temp_dict.get(key)
            else:
                return None
        return temp_dict


    def convert_resolution(self, value):
        """Converts resolution value (e.g., '1080p', '2160p', '4k') to a 0-4 scale."""
        if value is None or value == "":
            return None
        
        try:
            val_str = str(value).lower()
            
            # Extract numeric part
            numeric_match = re.search(r'\d+', val_str)
            if not numeric_match:
                return None
            
            numeric_value = int(numeric_match.group())
            
            # Handle 'k' notation (4k = 4000)
            if 'k' in val_str:
                numeric_value = numeric_value * 1000
            
            # Map to 0-4 scale
            if numeric_value <= 480:
                return 0  # SD
            elif numeric_value <= 720:
                return 1  # HD Ready
            elif numeric_value <= 1080:
                return 2  # Full HD
            elif numeric_value <= 1440:
                return 3  # 2K/QHD
            else:  # 2160 and above
                return 4  # 4K/UHD
                
        except (ValueError, TypeError, AttributeError):
            return None


    def convert_frame_rate(self, value):
        """Converts frame rate value (e.g., '60fps', '30fps') to a 0-4 scale."""
        if value is None or value == "":
            return None
        
        try:
            val_str = str(value).lower()
            
            # Extract numeric part
            numeric_match = re.search(r'\d+', val_str)
            if not numeric_match:
                return None
            
            numeric_value = int(numeric_match.group())
            
            # Map to 0-4 scale
            if numeric_value <= 24:
                return 0  # Cinema standard
            elif numeric_value <= 30:
                return 1  # Standard
            elif numeric_value <= 60:
                return 2  # High
            elif numeric_value <= 120:
                return 3  # Very high
            else:
                return 4  # Ultra high
                
        except (ValueError, TypeError, AttributeError):
            return None


    def convert_latency(self, value):
        """Converts latency string (e.g., '50ms', '100ms') to a 0-1 scale."""
        if value is None or value == "":
            return None
        
        try:
            val_str = str(value).lower()
            
            # Extract numeric part
            numeric_match = re.search(r'\d+', val_str)
            if not numeric_match:
                return None
            
            numeric_value = int(numeric_match.group())
            
            # 0 = low latency (good), 1 = high latency (bad)
            return 0 if numeric_value < 100 else 1
            
        except (ValueError, TypeError, AttributeError):
            return None


    def convert_adaptive_streaming(self, value):
        """Converts adaptive streaming boolean to a 0-1 scale."""
        if value is None:
            return None
        
        if isinstance(value, bool):
            return 0 if value else 1  # 0 = enabled (good), 1 = disabled
        
        val_str = str(value).lower()
        if val_str in ['true', 'yes', 'on', 'enable', 'enabled', '1']:
            return 0
        elif val_str in ['false', 'no', 'off', 'disable', 'disabled', '0']:
            return 1
        
        return None


    def convert_buffer_strategy(self, value):
        """Converts buffer strategy string to a 0-2 scale."""
        if value is None or value == "":
            return None
        
        val_str = str(value).lower()
        
        if 'aggressive' in val_str:
            return 0  # Most buffering
        elif 'balanced' in val_str:
            return 1  # Moderate buffering
        elif 'conservative' in val_str:
            return 2  # Least buffering
        
        return None


    def process_and_convert_intents(self, intents_dict):
        """
        Takes the raw nested dictionary from Pydantic model and converts it 
        into a flat dictionary with numeric values.
        """
        if not isinstance(intents_dict, dict):
            return {}

        # Extract raw values from nested structure
        raw_resolution = self.get_nested_value(intents_dict, ['video_quality', 'resolution'])
        raw_frame_rate = self.get_nested_value(intents_dict, ['video_quality', 'frame_rate'])
        raw_latency = self.get_nested_value(intents_dict, ['network_requirements', 'max_latency'])
        raw_adaptive = self.get_nested_value(intents_dict, ['network_requirements', 'adaptive_streaming'])
        raw_buffer = self.get_nested_value(intents_dict, ['reliability', 'buffer_strategy'])
        raw_movie_name = self.get_nested_value(intents_dict, ['movie_details', 'movie_name'])

        # Convert to numeric values
        processed_intents = {
            "resolution": self.convert_resolution(raw_resolution),
            "frame_rate": self.convert_frame_rate(raw_frame_rate),
            "latency": self.convert_latency(raw_latency),
            "adaptive_streaming": self.convert_adaptive_streaming(raw_adaptive),
            "buffer_strategy": self.convert_buffer_strategy(raw_buffer),
            "movie_title": raw_movie_name if raw_movie_name else ""
        }
        
        return processed_intents


    def create_intent_vector(self, intent_json):
        """
        Creates a vector (list) from the processed intents in a fixed order.
        Only includes numeric values, excludes movie_title.
        """
        ordered_keys = [
            "resolution",
            "frame_rate",
            "latency",
            "adaptive_streaming",
            "buffer_strategy"
        ]
        
        vector = [intent_json.get(key) for key in ordered_keys]
        return vector