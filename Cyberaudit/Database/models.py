"""
Модели базы данных для CyberAudit
"""

import os
from sqlalchemy import Column, String, Integer, DateTime, JSON, Boolean, Text, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime
