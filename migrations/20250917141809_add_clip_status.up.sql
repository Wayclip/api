-- Add a status column to track upload progress
ALTER TABLE clips
ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'completed';

-- Update existing clips to have the 'completed' status
UPDATE clips SET status = 'completed';
