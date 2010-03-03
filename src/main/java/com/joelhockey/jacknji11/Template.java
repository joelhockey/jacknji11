package com.joelhockey.jacknji11;

import com.sun.jna.Memory;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.PointerType;

public class Template extends PointerType {
    private int listLen;

    public Template() {
        this(null);
    }
    public Template(CK_ATTRIBUTE[] list) {
        listLen = list == null ? 0 : list.length;
        if (listLen == 0) {
            return;
        }
        setPointer(new Memory(listLen * (NativeLong.SIZE + Pointer.SIZE + NativeLong.SIZE)));
        int offset = 0;

        if (NativeLong.SIZE == 4) {
            for (int i = 0; i < listLen; i++) {
                getPointer().setInt(offset, list[i].type);
                offset += 4;
                getPointer().setPointer(offset, list[i].pValue);
                offset += Pointer.SIZE;
                getPointer().setInt(offset, list[i].ulValueLen);
                offset += 4;
            }
        } else {
            for (int i = 0; i < listLen; i++) {
                getPointer().setLong(offset, list[i].type);
                offset += 8;
                getPointer().setPointer(offset, list[i].pValue);
                offset += Pointer.SIZE;
                getPointer().setLong(offset, list[i].ulValueLen);
                offset += 8;
            }
        }
        
    }

    public void update(CK_ATTRIBUTE[] list) {
        if (listLen == 0) {
            return;
        }
        int offset = 0;
        if (NativeLong.SIZE == 4) {
            for (int i = 0; i < list.length; i++) {
                offset += 4 + Pointer.SIZE;
                list[i].ulValueLen = getPointer().getInt(offset);
                offset += 4;
            }
        } else {
            for (int i = 0; i < listLen; i++) {
                offset += 8 + Pointer.SIZE;
                list[i].ulValueLen = (int) getPointer().getLong(offset);
                offset += 8;
            }
        }
    }
    
}
