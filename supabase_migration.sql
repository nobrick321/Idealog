-- -------------------------------------------------------------
-- IDEALOG MULTI-USER REAL-TIME COLLABORATION MIGRATION SCHEMA
-- Run this inside your Supabase Project SQL Editor
-- -------------------------------------------------------------

-- Enable UUID extension if not enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Create tasks table
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    parent_id TEXT REFERENCES tasks(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    status TEXT DEFAULT 'todo',
    assignee TEXT,
    notes TEXT DEFAULT '',
    tags TEXT[] DEFAULT '{}',
    depth INTEGER NOT NULL,
    created_by TEXT, -- Tracks task creator display name/email
    created_at TIMESTAMP WITH TIME ZONE DEFAULT TIMEZONE('utc'::text, NOW()),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT TIMEZONE('utc'::text, NOW()),
    done_at TIMESTAMP WITH TIME ZONE
);

-- Index critical foreign key mappings for speed
CREATE INDEX IF NOT EXISTS idx_tasks_parent_id ON tasks(parent_id);

-- 2. Create object lists table
CREATE TABLE IF NOT EXISTS object_lists (
    id SERIAL PRIMARY KEY,
    category TEXT NOT NULL, -- 'assignees', 'systems', 'subsystems', 'projects', 'custom_xxx'
    value TEXT NOT NULL,
    UNIQUE (category, value)
);

-- Index lookups
CREATE INDEX IF NOT EXISTS idx_object_lists_category ON object_lists(category);

-- 3. Create task comments table
CREATE TABLE IF NOT EXISTS task_comments (
    id TEXT PRIMARY KEY,
    task_id TEXT REFERENCES tasks(id) ON DELETE CASCADE,
    author TEXT NOT NULL,
    content TEXT NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT TIMEZONE('utc'::text, NOW())
);

CREATE INDEX IF NOT EXISTS idx_task_comments_task_id ON task_comments(task_id);

-- 4. Create task history events table
CREATE TABLE IF NOT EXISTS task_history_events (
    id SERIAL PRIMARY KEY,
    task_id TEXT REFERENCES tasks(id) ON DELETE CASCADE,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT TIMEZONE('utc'::text, NOW()),
    author TEXT NOT NULL,
    field TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT
);

CREATE INDEX IF NOT EXISTS idx_task_history_events_task_id ON task_history_events(task_id);

-- 5. Create user profiles & roles table
CREATE TABLE IF NOT EXISTS user_profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT UNIQUE NOT NULL,
    display_name TEXT,
    role TEXT DEFAULT 'viewer' CHECK (role IN ('admin', 'manager', 'basic', 'viewer')),
    last_login TIMESTAMP WITH TIME ZONE DEFAULT TIMEZONE('utc'::text, NOW())
);

-- Index roles for speed
CREATE INDEX IF NOT EXISTS idx_user_profiles_role ON user_profiles(role);

-- -------------------------------------------------------------
-- AUTOMATED USER CREATION TRIGGER
-- Whenever a user signs up/logs in, automatically create their
-- profile in the public user_profiles table.
-- -------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO public.user_profiles (id, email, display_name, role)
    VALUES (
        new.id,
        new.email,
        COALESCE(new.raw_user_meta_data->>'name', split_part(new.email, '@', 1)),
        -- Default "Rits" email (or workspace owner) to admin, others default to viewer
        CASE 
            WHEN new.email = 'ritesh@morphle.in' THEN 'admin'
            ELSE 'viewer'
        END
    )
    ON CONFLICT (id) DO UPDATE
    SET last_login = TIMEZONE('utc'::text, NOW());
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Trigger definition
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- Ensure existing users are populated on migration
INSERT INTO public.user_profiles (id, email, display_name, role)
SELECT 
    id, 
    email, 
    COALESCE(raw_user_meta_data->>'name', split_part(email, '@', 1)),
    CASE 
        WHEN email = 'ritesh@morphle.in' THEN 'admin'
        ELSE 'viewer'
    END
FROM auth.users
ON CONFLICT (id) DO NOTHING;

-- -------------------------------------------------------------
-- ROW LEVEL SECURITY (RLS) POLICIES
-- Protect data so users can only perform actions allowed by
-- their role.
-- -------------------------------------------------------------

-- Enable RLS on all tables
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE object_lists ENABLE ROW LEVEL SECURITY;
ALTER TABLE task_comments ENABLE ROW LEVEL SECURITY;
ALTER TABLE task_history_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_profiles ENABLE ROW LEVEL SECURITY;

-- Helper function to fetch current user's role
CREATE OR REPLACE FUNCTION public.get_current_user_role()
RETURNS TEXT AS $$
DECLARE
    user_role TEXT;
BEGIN
    SELECT role INTO user_role 
    FROM public.user_profiles 
    WHERE id = auth.uid();
    RETURN COALESCE(user_role, 'viewer');
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 1. Policies for tasks table
CREATE POLICY "Viewers and above can read tasks" ON tasks
    FOR SELECT USING (true);

CREATE POLICY "Basic and above can update status/notes/assignee" ON tasks
    FOR UPDATE USING (
        public.get_current_user_role() IN ('admin', 'manager', 'basic')
    );

CREATE POLICY "Admin and Manager can insert tasks" ON tasks
    FOR INSERT WITH CHECK (
        public.get_current_user_role() IN ('admin', 'manager')
    );

CREATE POLICY "Admin and Manager can delete tasks" ON tasks
    FOR DELETE USING (
        public.get_current_user_role() IN ('admin', 'manager')
    );

-- 2. Policies for object_lists table
CREATE POLICY "Viewers and above can read object lists" ON object_lists
    FOR SELECT USING (true);

CREATE POLICY "Admin and Manager can modify object lists" ON object_lists
    FOR ALL USING (
        public.get_current_user_role() IN ('admin', 'manager')
    );

-- 3. Policies for task_comments table
CREATE POLICY "Viewers and above can read comments" ON task_comments
    FOR SELECT USING (true);

CREATE POLICY "Basic and above can post comments" ON task_comments
    FOR INSERT WITH CHECK (
        public.get_current_user_role() IN ('admin', 'manager', 'basic')
    );

CREATE POLICY "Only author or admin can delete comments" ON task_comments
    FOR DELETE USING (
        public.get_current_user_role() = 'admin' 
        OR (auth.uid()::text = author)
    );

-- 4. Policies for task_history_events table
CREATE POLICY "Everyone can read history" ON task_history_events
    FOR SELECT USING (true);

CREATE POLICY "Systems can insert history logs" ON task_history_events
    FOR INSERT WITH CHECK (
        public.get_current_user_role() IN ('admin', 'manager', 'basic')
    );

-- 5. Policies for user_profiles table
CREATE POLICY "Profiles are readable by everyone" ON public.user_profiles
    FOR SELECT USING (true);

CREATE POLICY "Users can edit their own profile details" ON public.user_profiles
    FOR UPDATE USING (auth.uid() = id);

CREATE POLICY "Only Admin can manage user roles" ON public.user_profiles
    FOR ALL USING (
        public.get_current_user_role() = 'admin'
    );
