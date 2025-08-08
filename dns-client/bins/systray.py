#!/usr/bin/env python3

import pystray
from PIL import Image, ImageDraw
import threading
import sys
import os
import subprocess
import logging
from client import DNSOverHTTPSClient, DNSForwarder, load_config

class DNSClientTray:
    def __init__(self, config_file=None):
        self.config_file = config_file
        self.config = {}
        self.dns_client = None
        self.forwarder = None
        self.forwarder_thread = None
        self.running = False
        
        if config_file:
            self.config = load_config(config_file)
        
        self.setup_logging()
        self.create_icon()
    
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    
    def create_image(self):
        """Create a simple DNS icon for the system tray"""
        width = 64
        height = 64
        image = Image.new('RGBA', (width, height), (0, 0, 0, 0))
        draw = ImageDraw.Draw(image)
        
        # Draw a simple DNS server icon (circle with network connections)
        # Main circle
        draw.ellipse([16, 16, 48, 48], fill=(0, 128, 255, 255), outline=(0, 64, 128, 255), width=2)
        
        # DNS text
        try:
            from PIL import ImageFont
            font = ImageFont.load_default()
            draw.text((24, 26), "DNS", fill=(255, 255, 255, 255), font=font)
        except:
            # If font loading fails, just draw simple lines
            draw.text((24, 26), "DNS", fill=(255, 255, 255, 255))
        
        # Network dots
        for x, y in [(8, 8), (56, 8), (8, 56), (56, 56)]:
            draw.ellipse([x-3, y-3, x+3, y+3], fill=(0, 200, 100, 255))
            # Lines to center
            draw.line([(x, y), (32, 32)], fill=(0, 200, 100, 128), width=1)
        
        return image
    
    def create_icon(self):
        """Create the system tray icon"""
        self.icon = pystray.Icon(
            "squawk_dns",
            self.create_image(),
            "Squawk DNS Client",
            menu=self.create_menu()
        )
    
    def create_menu(self):
        """Create the system tray menu"""
        return pystray.Menu(
            pystray.MenuItem("Start DNS Service", self.start_service, enabled=lambda item: not self.running),
            pystray.MenuItem("Stop DNS Service", self.stop_service, enabled=lambda item: self.running),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Open Console", self.open_console),
            pystray.MenuItem("Settings", self.open_settings),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Status", self.show_status),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit", self.quit_app)
        )
    
    def start_service(self, icon=None, item=None):
        """Start the DNS forwarding service"""
        if self.running:
            return
        
        try:
            # Load configuration
            dns_server_url = self.config.get('dns_server_url', 'https://dns.google/resolve')
            auth_token = self.config.get('auth_token')
            listen_udp = self.config.get('listen_udp', False)
            listen_tcp = self.config.get('listen_tcp', False)
            udp_port = self.config.get('udp_port', 53)
            tcp_port = self.config.get('tcp_port', 53)
            
            # Create DNS client and forwarder
            self.dns_client = DNSOverHTTPSClient(dns_server_url, auth_token)
            self.forwarder = DNSForwarder(
                self.dns_client, 
                udp_port=udp_port,
                tcp_port=tcp_port,
                listen_udp=listen_udp, 
                listen_tcp=listen_tcp
            )
            
            # Start forwarder in background thread
            if listen_udp or listen_tcp:
                self.forwarder_thread = threading.Thread(target=self.forwarder.start, daemon=True)
                self.forwarder_thread.start()
            
            self.running = True
            logging.info("DNS service started successfully")
            
            # Update icon to show active status
            self.update_icon_status(True)
            
            # Update menu
            self.icon.menu = self.create_menu()
            
        except Exception as e:
            logging.error(f"Failed to start DNS service: {e}")
            self.show_notification("Error", f"Failed to start DNS service: {e}")
    
    def stop_service(self, icon=None, item=None):
        """Stop the DNS forwarding service"""
        if not self.running:
            return
        
        try:
            # Stop the service
            self.running = False
            
            # The threads will naturally exit when the service stops
            if self.forwarder_thread:
                self.forwarder_thread = None
            
            self.dns_client = None
            self.forwarder = None
            
            logging.info("DNS service stopped")
            
            # Update icon to show inactive status
            self.update_icon_status(False)
            
            # Update menu
            self.icon.menu = self.create_menu()
            
        except Exception as e:
            logging.error(f"Failed to stop DNS service: {e}")
    
    def update_icon_status(self, active):
        """Update the icon to reflect active/inactive status"""
        # Create new image with status indicator
        image = self.create_image()
        draw = ImageDraw.Draw(image)
        
        # Add status indicator
        if active:
            # Green dot for active
            draw.ellipse([50, 50, 62, 62], fill=(0, 255, 0, 255))
        else:
            # Red dot for inactive
            draw.ellipse([50, 50, 62, 62], fill=(255, 0, 0, 255))
        
        self.icon.icon = image
    
    def open_console(self, icon=None, item=None):
        """Open the web console"""
        import webbrowser
        console_url = self.config.get('console_url', 'http://localhost:8080/dns_console')
        webbrowser.open(console_url)
    
    def open_settings(self, icon=None, item=None):
        """Open settings dialog or file"""
        if self.config_file and os.path.exists(self.config_file):
            # Open config file in default editor
            if sys.platform == 'win32':
                os.startfile(self.config_file)
            elif sys.platform == 'darwin':
                subprocess.run(['open', self.config_file])
            else:
                subprocess.run(['xdg-open', self.config_file])
        else:
            self.show_notification("Info", "No configuration file found")
    
    def show_status(self, icon=None, item=None):
        """Show current service status"""
        status = "Running" if self.running else "Stopped"
        server = self.config.get('dns_server_url', 'Not configured')
        
        message = f"Status: {status}\nServer: {server}"
        
        if self.running and self.forwarder:
            if self.forwarder.listen_udp:
                message += f"\nUDP Port: {self.forwarder.udp_port}"
            if self.forwarder.listen_tcp:
                message += f"\nTCP Port: {self.forwarder.tcp_port}"
        
        self.show_notification("DNS Service Status", message)
    
    def show_notification(self, title, message):
        """Show a system notification"""
        if hasattr(self.icon, 'notify'):
            self.icon.notify(message, title)
        else:
            logging.info(f"{title}: {message}")
    
    def quit_app(self, icon=None, item=None):
        """Quit the application"""
        self.stop_service()
        self.icon.stop()
        sys.exit(0)
    
    def run(self):
        """Run the system tray application"""
        # Auto-start service if configured
        if self.config.get('auto_start', False):
            self.start_service()
        
        self.icon.run()

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Squawk DNS Client System Tray')
    parser.add_argument('-c', '--config', help='Configuration file path')
    args = parser.parse_args()
    
    app = DNSClientTray(config_file=args.config)
    app.run()

if __name__ == "__main__":
    main()