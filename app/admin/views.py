import os
from . import admin
from flask import render_template, redirect, url_for, flash, session, request
from app.admin.forms import LoginForm, TagForm, MovieForm, PreviewForm, PwdForm
from app.models import Admin, Tag, Movie, Preview, User, Auth, Role, Comment, Moviecol, Oplog, Adminlog, Userlog
from functools import wraps
from app import db, app
from werkzeug.utils import secure_filename
import uuid
from datetime import datetime


# 上下文应用处理器
@admin.context_processor
def tpl_extra():
    data = dict(
        online_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    return data


def admin_auth(f):
    """
    权限控制装饰器
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        admin = Admin.query.join(Role).filter(Role.id == Admin.role_id, Admin.id == session["admin_id"]).first()
        auths = admin.role.auths
        auths = list(map(lambda v: int(v), auths.split(",")))
        auth_list = Auth.query.all()
        urls = [v.url for v in auth_list for val in auths if val == v.id]
        rule = request.url_rule
        if str(rule) not in urls:
            os.abort(404)
        return f(*args, **kwargs)

    return decorated_function


def admin_login_req(f):
    """
    登录装饰器
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "admin" not in session:
            return redirect(url_for("admin.login", next=request.url))
        return f(*args, **kwargs)

    return decorated_function


# 修改文件名
def change_filename(filename):
    fileinfo = os.path.splitext(filename)
    filename = datetime.now().strftime("%Y%m%d%H%M%S") + str(uuid.uuid4().hex) + fileinfo[-1]
    return filename


@admin.route("/")
@admin_login_req
def index():
    return render_template("admin/index.html")


# 登录
@admin.route("/login/", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        data = form.data
        admin = Admin.query.filter_by(name=data["account"]).first()
        if not admin.check_pwd(data["pwd"]):
            flash("账号密码错误,请重新输入", "err")
            return redirect(url_for("admin.login"))
        session["admin"] = data["account"]
        session["admin_id"] = admin.id
        adminlog = Adminlog(
            admin_id=admin.id,
            ip=request.remote_addr
        )
        db.session.add(adminlog)
        db.session.commit()
        return redirect(request.args.get("next") or url_for("admin.index"))
    return render_template("admin/login.html", form=form)


@admin.route("/logout/")
@admin_login_req
def logout():
    session.pop("admin", None)
    return redirect(url_for("admin.login"))


@admin.route("/pwd/", methods=["GET", "POST"])
@admin_login_req
def pwd():
    form = PwdForm()
    if form.validate_on_submit():
        data = form.data
        admin = Admin.query.filter_by(name=session["admin"]).first()
        from werkzeug.security import generate_password_hash
        admin.pwd = generate_password_hash(data["new_pwd"])
        db.session.add(admin)
        db.session.commit()
        flash("修改密码成功! 请重新登录!", "ok")
        return redirect(url_for("admin.logout"))
    return render_template("admin/pwd.html", form=form)


@admin.route("/tag/add/", methods=["GET", "POST"])
@admin_login_req
def tag_add():
    form = TagForm()
    if form.validate_on_submit():
        data = form.data
        tag = Tag.query.filter_by(name=data['name']).count()
        if tag == 1:
            flash("标签名已经存在", "err")
            return redirect(url_for("admin.tag_add"))
        tag = Tag(name=data["name"])
        db.session.add(tag)
        db.session.commit()
        flash("添加标签成功", "ok")
        oplog = Oplog(
            admin_id=session["admin_id"],
            ip=request.remote_addr,
            reason="添加标签%s" % data["name"]
        )
        db.session.add(oplog)
        db.session.commit()
        redirect(url_for("admin.tag_add"))

    return render_template("admin/tag_add.html", form=form)


@admin.route("/tag/list/<int:page>/", methods=["GET"])
@admin_login_req
def tag_list(page=None):
    if page is None:
        page = 1
    page_data = Tag.query.order_by(Tag.addtime.desc()).paginate(page=page, per_page=10)
    return render_template("admin/tag_list.html", page_data=page_data)


@admin.route("/tag/del/<int:id>/", methods=["GET"])
@admin_login_req
def tag_del(id=None):
    tag = Tag.query.filter_by(id=id).first_or_404()  # notes: first() or 404()
    db.session.delete(tag)
    db.session.commit()
    flash("删除标签成功", "ok")
    return redirect(url_for("admin.tag_list", page=1))


@admin.route("/tag/edit/<int:id>/", methods=["GET", "POST"])
@admin_login_req
def tag_edit(id=None):
    form = TagForm()
    tag = Tag.query.get_or_404(id)
    if form.validate_on_submit():
        data = form.data
        tag_count = Tag.query.filter_by(name=data['name']).count()
        if tag_count == 1 and data["name"] == tag.name:
            flash("标签名已经存在", "err")
            return redirect(url_for("admin.tag_edit", id=id))
        tag.name = data["name"]
        db.session.add(tag)
        db.session.commit()
        flash("编辑标签成功", "ok")
        redirect(url_for("admin.tag_edit", id=id))
    return render_template("admin/tag_edit.html", form=form, tag=tag)


@admin.route("/movie/add/", methods=["GET", "POST"])
@admin_login_req
def movie_add():
    form = MovieForm()
    if form.validate_on_submit():
        data = form.data
        file_url = secure_filename(form.url.data.filename)
        file_logo = secure_filename(form.logo.data.filename)
        if not os.path.exists(app.config["UP_DIR"]):
            os.makedirs(app.config["UP_DIR"])
            os.chmod(app.config["UP_DIR"], "rw")
        url = change_filename(file_url)
        logo = change_filename(file_logo)
        form.url.data.save(app.config["UP_DIR"] + url)
        form.logo.data.save(app.config["UP_DIR"] + logo)
        movie = Movie(title=data["title"], url=url, info=data["info"], logo=logo, star=int(data["star"]), playnum=0,
            commentnum=0, tag_id=int(data["tag_id"]), area=data["area"], release_time=data["release_time"],
            length=data["length"])
        db.session.add(movie)
        db.session.commit()
        flash("添加电影成功", "ok")
        return redirect(url_for("admin.movie_add"))
    return render_template("admin/movie_add.html", form=form)


@admin.route("/movie/list/<int:page>", methods=["GET"])
@admin_login_req
def movie_list(page=None):
    if page is None:
        page = 1
    page_data = Movie.query.join(Tag).filter(Tag.id == Movie.tag_id).order_by(Movie.addtime.desc()).paginate(page=page,
                                                                                                             per_page=10)
    return render_template("admin/movie_list.html", page_data=page_data)


@admin.route("/movie/del/<int:id>/", methods=["GET"])
@admin_login_req
def movie_del(id=None):
    """
    电影删除
    """
    movie = Movie.query.get_or_404(id)
    db.session.delete(movie)
    db.session.commit()
    flash("电影删除成功", "ok")
    return redirect(url_for('admin.movie_list', page=1))


@admin.route("/movie/edit/<int:id>/", methods=["GET", "POST"])
@admin_login_req
def movie_edit(id=None):
    """
    编辑电影页面
    """
    form = MovieForm()
    # 因为是编辑，所以非空验证空
    form.url.validators = []
    form.logo.validators = []
    movie = Movie.query.get_or_404(int(id))
    if request.method == "GET":
        form.info.data = movie.info
        form.tag_id.data = movie.tag_id
        form.star.data = movie.star
    if form.validate_on_submit():
        data = form.data
        movie_count = Movie.query.filter_by(title=data["title"]).count()
        # 存在一步名字叫这个的电影，有可能是它自己，也有可能是同名。如果是现在的movie不等于要提交的数据中title。那么说明有两个。
        if movie_count == 1 and movie.title == data["title"]:
            flash("片名已经存在！", "err")
            return redirect(url_for('admin.movie_edit', id=id))
        # 创建目录
        if not os.path.exists(app.config["UP_DIR"]):
            os.makedirs(app.config["UP_DIR"])
            os.chmod(app.config["UP_DIR"], "rw")
        # 上传视频
        if form.url.data != "":
            file_url = secure_filename(form.url.data.filename)
            movie.url = change_filename(file_url)
            form.url.data.save(app.config["UP_DIR"] + movie.url)
        # 上传图片
        if form.logo.data != "":
            file_logo = secure_filename(form.logo.data.filename)
            movie.logo = change_filename(file_logo)
            form.logo.data.save(app.config["UP_DIR"] + movie.logo)

        movie.star = int(data["star"])
        movie.tag_id = int(data["tag_id"])
        movie.info = data["info"]
        movie.title = data["title"]
        movie.area = data["area"]
        movie.length = data["length"]
        movie.release_time = data["release_time"]
        db.session.add(movie)
        db.session.commit()
        flash("修改电影成功！", "ok")
        return redirect(url_for('admin.movie_edit', id=id))
    return render_template("admin/movie_edit.html", form=form, movie=movie)


@admin.route("/preview/add/", methods=["GET", "POST"])
@admin_login_req
def preview_add():
    form = PreviewForm()
    if form.validate_on_submit():
        data = form.data
        file_logo = secure_filename(form.logo.data.filename)
        if not os.path.exists(app.config["UP_DIR"]):
            os.makedirs(app.config["UP_DIR"])
            os.chmod(app.config["UP_DIR"], "rw")
        logo = change_filename(file_logo)
        form.logo.data.save(app.config["UP_DIR"] + logo)
        preview = Preview(title=data["title"], logo=logo)
        db.session.add(preview)
        db.session.commit()
        flash("编辑预告成功", "ok")
        return redirect(url_for("admin.preview_add"))
    return render_template("admin/preview_add.html", form=form)


@admin.route("/preview/list/<int:page>/", methods=["GET"])
@admin_login_req
def preview_list(page=None):
    if page is None:
        page = 1
    page_data = Preview.query.order_by(Preview.addtime.desc()).paginate(page=page, per_page=10)
    return render_template("admin/preview_list.html", page_data=page_data)


@admin.route("/preview/del/<int:id>/", methods=["GET"])
@admin_login_req
def preview_del(id=None):
    """
    电影删除
    """
    preview = Preview.query.get_or_404(id)
    db.session.delete(preview)
    db.session.commit()
    flash("电影删除成功", "ok")
    return redirect(url_for('admin.preview_list', page=1))


@admin.route("/preview/edit/<int:id>/", methods=["GET", "POST"])
@admin_login_req
def preview_edit(id):
    form = PreviewForm()
    preview = Preview.query.get_or_404(int(id))
    if request.method == "GET":
        form.title.data = preview.title
    if form.validate_on_submit():
        data = form.data
        if form.logo.data != "":
            file_logo = secure_filename(form.logo.data.filename)
            preview.logo = change_filename(file_logo)
            form.logo.data.save(app.config["UP_DIR"] + preview.logo)
        preview.title = data["title"]
        db.session.add(preview)
        db.session.commit()
        flash("编辑预告成功", "ok")
        return redirect(url_for("admin.preview_edit", id=id))
    return render_template("admin/preview_edit.html", form=form, preview=preview)


@admin.route("/user/list/<int:page>/", methods=["GET"])
@admin_login_req
def user_list(page):
    if page is None:
        page = 1
    page_data = User.query.order_by(
        User.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/user_list.html", page_data=page_data)


@admin.route("/user/view/<int:id>/", methods=["GET"])
@admin_login_req
def user_view(id=None):
    user = User.query.get_or_404(int(id))

    return render_template("admin/user_view.html", user=user)


@admin.route("/user/del/<int:id>/", methods=["GET"])
@admin_login_req
def user_del(id=None):
    """
    电影删除
    """
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    flash("用户删除成功", "ok")
    return redirect(url_for('admin.user_list', page=1))


@admin.route("/comment/list/<int:page>/", methods=["GET"])
@admin_login_req
def comment_list(page=None):
    if page is None:
        page = 1
    page_data = Comment.query.join(
        Movie
    ).join(
        User
    ).filter(
        Movie.id == Comment.movie_id,
        User.id == Comment.user_id).order_by(
        Comment.addtime.desc()).paginate(page=page, per_page=10)
    return render_template("admin/comment_list.html", page_data=page_data)


@admin.route("/comment/del/<int:id>/", methods=["GET"])
@admin_login_req
def comment_del(id=None):
    """
    电影删除
    """
    comment = Comment.query.get_or_404(id)
    db.session.delete(comment)
    db.session.commit()
    flash("评论删除成功", "ok")
    return redirect(url_for('admin.comment_list', page=1))


@admin.route("/moviecol/list/<int:page>/", methods=["GET"])
@admin_login_req
def moviecol_list(page):
    if page is None:
        page = 1
    page_data = Moviecol.query.join(
        Movie
    ).join(
        User
    ).filter(
        Moviecol.movie_id == Movie.id,
        Moviecol.user_id == User.id
    ).order_by(
        Moviecol.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/moviecol_list.html", page_data=page_data)


@admin.route("/moviecol/del/<int:id>/")
@admin_login_req
def moviecol_del(id=None):
    moviecol = Moviecol.query.get_or_404(int(id))
    db.session.delete(moviecol)
    db.session.commit()
    flash("删除收藏成功", "ok")
    return redirect(url_for("admin.moviecol_list", page=1))


@admin.route("/oplog/list/<int:page>/", methods=["GET"])
@admin_login_req
def oplog_list(page=None):
    if page is None:
        page = 1
    page_data = Oplog.query.join(
        Admin
    ).filter(
        Oplog.admin_id == Admin.id
    ).order_by(
        Oplog.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/oplog_list.html", page_data=page_data)


@admin.route("/adminloginlog/list/<int:page>/", methods=["GET"])
@admin_login_req
def adminloginlog_list(page=None):
    if page is None:
        page = 1
    page_data = Adminlog.query.join(
        Admin
    ).filter(
        Adminlog.admin_id == Admin.id
    ).order_by(
        Adminlog.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/adminloginlog_list.html", page_data=page_data)


@admin.route("/userloginlog/list/<int:page>/", methods=["GET"])
@admin_login_req
def userloginlog_list(page=None):
    if page is None:
        page = 1
    page_data = Userlog.query.join(
        User
    ).filter(
        User.id == Userlog.user_id
    ).order_by(
        Userlog.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/userloginlog_list.html", page_data=page_data)


@admin.route("/role/add/")
@admin_login_req
def role_add():
    return render_template("admin/role_add.html")


@admin.route("/role/list/")
@admin_login_req
def role_list():
    return render_template("admin/role_list.html")


@admin.route("/auth/add/")
@admin_login_req
def auth_add():
    return render_template("admin/auth_add.html")


@admin.route("/auth/list/")
@admin_login_req
def auth_list():
    return render_template("admin/auth_list.html")


@admin.route("/admin/add/")
@admin_login_req
def admin_add():
    return render_template("admin/admin_add.html")


@admin.route("/admin/list/")
@admin_login_req
def admin_list():
    return render_template("admin/admin_list.html")
