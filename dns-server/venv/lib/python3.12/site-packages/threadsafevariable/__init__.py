import copy
import threading


__version__ = 20230507.1


class ThreadSafeVariable:

    storage = threading.local()
    master_thread = threading.current_thread()
    defaults = {}

    def __set__(self, instance, value):
        key = "%s.%s" % (id(instance), id(self))
        if self.master_thread == threading.current_thread():
            self.defaults[key] = value
        setattr(self.storage, key, value)

    def __get__(self, instance, owner):
        key = "%s.%s" % (id(instance), id(self))
        return getattr(
            self.storage,
            key,
            self.defaults.get(key))
    

    @staticmethod
    def freeze():
        return copy.copy(ThreadSafeVariable.storage.__dict__)

    @staticmethod
    def restore(image):
        for key in image:
            setattr(ThreadSafeVariable.storage, key, image[key])
