package org.papercraft.ui.Components;

import android.app.Activity;
import android.graphics.Bitmap;
import android.view.MotionEvent;
import android.view.View;

import org.papercraft.messenger.VideoEditedInfo;
import org.papercraft.tgnet.TLRPC;
import org.papercraft.ui.Components.Paint.RenderView;
import org.papercraft.ui.PhotoViewer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public interface IPhotoPaintView {
    default View getView() {
        if (this instanceof View) {
            return (View) this;
        }
        throw new IllegalArgumentException("You should override getView() if you're not inheriting from it.");
    }

    void init();
    void shutdown();
    void onResume();

    void setOffsetTranslationY(float y, float panProgress, int keyboardHeight, boolean isPan);
    float getOffsetTranslationY();
    void updateColors();
    boolean hasChanges();
    Bitmap getBitmap(ArrayList<VideoEditedInfo.MediaEntity> entities, Bitmap[] thumbBitmap);
    long getLcm();
    View getDoneView();
    View getCancelView();
    void maybeShowDismissalAlert(PhotoViewer photoViewer, Activity parentActivity, Runnable okRunnable);
    boolean onTouch(MotionEvent ev);
    void setTransform(float scale, float trX, float trY, float imageWidth, float imageHeight);
    void setOnDoneButtonClickedListener(Runnable callback);
    void onBackPressed();
    int getEmojiPadding(boolean panned);
    RenderView getRenderView();

    void updateZoom(boolean zoomedOut);

    float adjustPanLayoutHelperProgress();

    default int getAdditionalBottom() {
        return 0;
    }

    default int getAdditionalTop() {
        return 0;
    }

    default List<TLRPC.InputDocument> getMasks() {
        return Collections.emptyList();
    }

    default void onCleanupEntities() {}
}
