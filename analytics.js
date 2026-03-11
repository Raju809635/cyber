// Advanced Analytics and User Tracking
class AnalyticsService {
    constructor() {
        this.sessionId = this.generateSessionId();
        this.startTime = Date.now();
        this.events = [];
    }

    generateSessionId() {
        return 'session_' + Math.random().toString(36).substr(2, 9) + '_' + Date.now();
    }

    // Track user events
    trackEvent(eventName, properties = {}) {
        const event = {
            name: eventName,
            properties: {
                ...properties,
                sessionId: this.sessionId,
                timestamp: Date.now(),
                url: window.location.href,
                userAgent: navigator.userAgent,
                screenResolution: `${screen.width}x${screen.height}`,
                language: navigator.language
            }
        };

        this.events.push(event);

        // Send to Firebase Analytics
        if (window.gtag) {
            gtag('event', eventName, properties);
        }

        // Send to Firestore
        this.saveEventToFirestore(event);

        console.log('Event tracked:', event);
    }

    // Save event to Firestore
    async saveEventToFirestore(event) {
        try {
            if (window.firebaseServices && window.firebaseServices.db) {
                await window.firebaseServices.db.collection('analytics_events').add({
                    ...event,
                    timestamp: firebase.firestore.FieldValue.serverTimestamp()
                });
            }
        } catch (error) {
            console.error('Error saving event to Firestore:', error);
        }
    }

    // Track page views
    trackPageView(pageName) {
        this.trackEvent('page_view', {
            page_name: pageName,
            page_title: document.title
        });
    }

    // Track user interactions
    trackClick(elementId, elementText) {
        this.trackEvent('click', {
            element_id: elementId,
            element_text: elementText
        });
    }

    // Track form submissions
    trackFormSubmission(formName, success = true) {
        this.trackEvent('form_submit', {
            form_name: formName,
            success: success
        });
    }

    // Track errors
    trackError(errorMessage, errorStack) {
        this.trackEvent('error', {
            error_message: errorMessage,
            error_stack: errorStack
        });
    }

    // Track user session duration
    trackSessionEnd() {
        const sessionDuration = Date.now() - this.startTime;
        this.trackEvent('session_end', {
            session_duration: sessionDuration,
            events_count: this.events.length
        });
    }

    // Get user analytics data
    async getUserAnalytics(userId) {
        try {
            if (!window.firebaseServices || !window.firebaseServices.db) {
                return null;
            }

            const db = window.firebaseServices.db;
            
            // Get user events from last 30 days
            const thirtyDaysAgo = new Date();
            thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

            const eventsSnapshot = await db.collection('analytics_events')
                .where('properties.userId', '==', userId)
                .where('timestamp', '>=', thirtyDaysAgo)
                .orderBy('timestamp', 'desc')
                .limit(1000)
                .get();

            const events = [];
            eventsSnapshot.forEach(doc => {
                events.push({ id: doc.id, ...doc.data() });
            });

            // Calculate analytics
            const analytics = {
                totalEvents: events.length,
                uniqueSessions: new Set(events.map(e => e.properties.sessionId)).size,
                pageViews: events.filter(e => e.name === 'page_view').length,
                clicks: events.filter(e => e.name === 'click').length,
                errors: events.filter(e => e.name === 'error').length,
                lastActivity: events.length > 0 ? events[0].timestamp : null,
                topPages: this.getTopPages(events),
                deviceInfo: this.getDeviceInfo(events),
                timeSpent: this.calculateTimeSpent(events)
            };

            return analytics;

        } catch (error) {
            console.error('Error getting user analytics:', error);
            return null;
        }
    }

    // Get top pages visited
    getTopPages(events) {
        const pageViews = events.filter(e => e.name === 'page_view');
        const pageCounts = {};
        
        pageViews.forEach(event => {
            const page = event.properties.page_name || 'unknown';
            pageCounts[page] = (pageCounts[page] || 0) + 1;
        });

        return Object.entries(pageCounts)
            .sort(([,a], [,b]) => b - a)
            .slice(0, 10)
            .map(([page, count]) => ({ page, count }));
    }

    // Get device information
    getDeviceInfo(events) {
        if (events.length === 0) return {};

        const latestEvent = events[0];
        return {
            userAgent: latestEvent.properties.userAgent,
            screenResolution: latestEvent.properties.screenResolution,
            language: latestEvent.properties.language
        };
    }

    // Calculate time spent on site
    calculateTimeSpent(events) {
        const sessions = {};
        
        events.forEach(event => {
            const sessionId = event.properties.sessionId;
            if (!sessions[sessionId]) {
                sessions[sessionId] = {
                    start: event.timestamp,
                    end: event.timestamp
                };
            } else {
                sessions[sessionId].start = Math.min(sessions[sessionId].start, event.timestamp);
                sessions[sessionId].end = Math.max(sessions[sessionId].end, event.timestamp);
            }
        });

        const totalTime = Object.values(sessions).reduce((total, session) => {
            return total + (session.end - session.start);
        }, 0);

        return Math.round(totalTime / 1000); // Return in seconds
    }

    // Initialize event listeners
    initializeTracking() {
        // Track page load
        this.trackPageView(window.location.pathname);

        // Track clicks on buttons and links
        document.addEventListener('click', (event) => {
            if (event.target.tagName === 'BUTTON' || event.target.tagName === 'A') {
                this.trackClick(
                    event.target.id || 'unknown',
                    event.target.textContent.trim().substring(0, 50)
                );
            }
        });

        // Track form submissions
        document.addEventListener('submit', (event) => {
            const formName = event.target.id || event.target.className || 'unknown_form';
            this.trackFormSubmission(formName);
        });

        // Track errors
        window.addEventListener('error', (event) => {
            this.trackError(event.message, event.error ? event.error.stack : '');
        });

        // Track session end on page unload
        window.addEventListener('beforeunload', () => {
            this.trackSessionEnd();
        });

        // Track visibility changes
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                this.trackEvent('page_hidden');
            } else {
                this.trackEvent('page_visible');
            }
        });
    }
}

// Initialize analytics service
window.analyticsService = new AnalyticsService();

// Auto-initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.analyticsService.initializeTracking();
});