module Badges
  class AwardBelovedComment
    BADGE_SLUG = "beloved-comment".freeze

    def self.call(comment_count = 25)
      new(comment_count).call
    end

    def initialize(comment_count)
      @comment_count = comment_count
    end

    def call
      badge_id = Badge.find_by(slug: BADGE_SLUG)&.id
      return unless badge_id

      Comment.includes(:user).where(public_reactions_count: comment_count..).find_each do |comment|
        achievement = BadgeAchievement.create(
          user_id: comment.user_id,
          badge_id: badge_id,
          rewarding_context_message_markdown: generate_message(comment),
        )
        comment.user.touch if achievement.valid?
      end
    end

    private

    attr_reader :comment_count

    def generate_message(comment)
      "You're famous! " \
        "[This is the comment](#{URL.comment(comment)}) for which you are being recognized. 😄"
    end
  end
end
