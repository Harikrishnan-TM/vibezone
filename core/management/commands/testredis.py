from django.core.management.base import BaseCommand
import os
import redis

class Command(BaseCommand):
    help = "Test Redis connection"

    def handle(self, *args, **kwargs):
        try:
            redis_url = os.getenv("UPSTASH_REDIS_URL")
            r = redis.from_url(redis_url)

            r.set("redis_test", "working")
            val = r.get("redis_test")
            self.stdout.write(self.style.SUCCESS(f"✅ Redis test successful: {val.decode('utf-8')}"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ Redis test failed: {str(e)}"))
