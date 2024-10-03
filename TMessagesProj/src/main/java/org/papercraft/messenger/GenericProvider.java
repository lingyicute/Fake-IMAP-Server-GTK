package org.papercraft.messenger;

public interface GenericProvider<F, T> {
    T provide(F obj);
}
